/* Copyright 2017 Istio Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "src/envoy/transcoding/filter.h"

#include "common/common/enum_to_int.h"
#include "common/http/headers.h"
#include "common/http/utility.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/descriptor.pb.h"
#include "google/protobuf/message.h"
#include "google/protobuf/util/type_resolver.h"
#include "google/protobuf/util/type_resolver_util.h"
#include "server/config/network/http_connection_manager.h"

using google::protobuf::FileDescriptor;
using google::protobuf::FileDescriptorSet;
using google::protobuf::DescriptorPool;

namespace Envoy {
namespace Grpc {
namespace Transcoding {

const std::string kTypeUrlPrefix{"type.googleapis.com"};

const std::string kGrpcContentType{"application/grpc"};
const std::string kJsonContentType{"application/json"};
const Http::LowerCaseString kTeHeader{"te"};
const std::string kTeTrailers{"trailers"};

Instance::Instance(Config& config) : config_(config) {}

Http::FilterHeadersStatus Instance::decodeHeaders(Http::HeaderMap& headers,
                                                  bool end_stream) {
  log().debug("Transcoding::Instance::decodeHeaders");

  auto status = config_.CreateTranscoder(headers, &request_in_, &response_in_,
                                         transcoder_, method_);
  if (status.ok()) {
    headers.removeContentLength();
    headers.insertContentType().value(kGrpcContentType);
    headers.insertPath().value("/" + method_->service()->full_name() + "/" +
                               method_->name());

    headers.insertMethod().value(Http::Headers::get().MethodValues.Post);

    headers.addStatic(kTeHeader, kTeTrailers);

    if (end_stream) {
      log().debug("header only request");

      request_in_.Finish();

      const auto& request_status = transcoder_->RequestStatus();
      if (!request_status.ok()) {
        log().debug("Transcoding request error " + request_status.ToString());
        error_ = true;
        Http::Utility::sendLocalReply(
            *decoder_callbacks_, Http::Code::BadRequest,
            request_status.error_message().ToString());

        return Http::FilterHeadersStatus::StopIteration;
      }

      Buffer::OwnedImpl data;
      ReadToBuffer(transcoder_->RequestOutput(), data);

      if (data.length()) {
        decoder_callbacks_->addDecodedData(data);
      }
    }
  } else {
    log().debug("No transcoding: " + status.ToString());
  }

  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus Instance::decodeData(Buffer::Instance& data,
                                            bool end_stream) {
  log().debug("Transcoding::Instance::decodeData");

  if (error_) {
    return Http::FilterDataStatus::StopIterationNoBuffer;
  }

  if (transcoder_) {
    request_in_.Move(data);

    if (end_stream) {
      request_in_.Finish();
    }

    ReadToBuffer(transcoder_->RequestOutput(), data);

    const auto& request_status = transcoder_->RequestStatus();

    if (!request_status.ok()) {
      log().debug("Transcoding request error " + request_status.ToString());
      error_ = true;
      Http::Utility::sendLocalReply(*decoder_callbacks_, Http::Code::BadRequest,
                                    request_status.error_message().ToString());

      return Http::FilterDataStatus::StopIterationNoBuffer;
    }
  }

  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus Instance::decodeTrailers(Http::HeaderMap& trailers) {
  log().debug("Transcoding::Instance::decodeTrailers");
  if (transcoder_) {
    request_in_.Finish();

    Buffer::OwnedImpl data;
    ReadToBuffer(transcoder_->RequestOutput(), data);

    if (data.length()) {
      decoder_callbacks_->addDecodedData(data);
    }
  }

  return Http::FilterTrailersStatus::Continue;
}

void Instance::setDecoderFilterCallbacks(
    Http::StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}

Http::FilterHeadersStatus Instance::encodeHeaders(Http::HeaderMap& headers,
                                                  bool end_stream) {
  log().debug("Transcoding::Instance::encodeHeaders {}", end_stream);
  if (error_) {
    return Http::FilterHeadersStatus::Continue;
  }

  if (transcoder_) {
    response_headers_ = &headers;
    headers.insertContentType().value(kJsonContentType);
    if (!method_->server_streaming() && !end_stream) {
      return Http::FilterHeadersStatus::StopIteration;
    }
  }
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus Instance::encodeData(Buffer::Instance& data,
                                            bool end_stream) {
  log().debug("Transcoding::Instance::encodeData");
  if (error_) {
    return Http::FilterDataStatus::Continue;
  }

  if (transcoder_) {
    response_in_.Move(data);

    if (end_stream) {
      response_in_.Finish();
    }

    ReadToBuffer(transcoder_->ResponseOutput(), data);

    if (!method_->server_streaming()) {
      return Http::FilterDataStatus::StopIterationAndBuffer;
    }
    // TODO: Check ResponseStatus
  }

  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus Instance::encodeTrailers(Http::HeaderMap& trailers) {
  log().debug("Transcoding::Instance::encodeTrailers");
  if (transcoder_) {
    response_in_.Finish();

    Buffer::OwnedImpl data;
    ReadToBuffer(transcoder_->ResponseOutput(), data);

    if (data.length()) {
      encoder_callbacks_->addEncodedData(data);
    }

    if (!method_->server_streaming()) {
      const Http::HeaderEntry* grpc_status_header = trailers.GrpcStatus();
      if (grpc_status_header) {
        uint64_t grpc_status_code;
        if (!StringUtil::atoul(grpc_status_header->value().c_str(),
                               grpc_status_code)) {
          response_headers_->Status()->value(
              enumToInt(Http::Code::ServiceUnavailable));
        }
        response_headers_->insertGrpcStatus().value(*grpc_status_header);
      }

      const Http::HeaderEntry* grpc_message_header = trailers.GrpcMessage();
      if (grpc_message_header) {
        response_headers_->insertGrpcMessage().value(*grpc_message_header);
      }

      response_headers_->insertContentLength().value(
          encoder_callbacks_->encodingBuffer()
              ? encoder_callbacks_->encodingBuffer()->length()
              : 0);
    }
  }
  return Http::FilterTrailersStatus::Continue;
}

void Instance::setEncoderFilterCallbacks(
    Http::StreamEncoderFilterCallbacks& callbacks) {
  encoder_callbacks_ = &callbacks;
}

bool Instance::ReadToBuffer(google::protobuf::io::ZeroCopyInputStream* stream,
                            Buffer::Instance& data) {
  const void* out;
  int size;
  while (stream->Next(&out, &size)) {
    data.add(out, size);

    if (size == 0) {
      return true;
    }
  }
  return false;
}

}  // namespace Transcoding
}  // namespace Grpc

namespace Server {
namespace Configuration {

class TranscodingConfig : public HttpFilterConfigFactory {
 public:
  HttpFilterFactoryCb tryCreateFilterFactory(
      HttpFilterType type, const std::string& name, const Json::Object& config,
      const std::string&, Server::Instance& server) override {
    if (type != HttpFilterType::Both || name != "transcoding") {
      return nullptr;
    }

    Grpc::Transcoding::ConfigSharedPtr transcoding_config{
        new Grpc::Transcoding::Config(config)};
    return [transcoding_config](
               Http::FilterChainFactoryCallbacks& callbacks) -> void {
      std::shared_ptr<Grpc::Transcoding::Instance> instance =
          std::make_shared<Grpc::Transcoding::Instance>(*transcoding_config);
      callbacks.addStreamFilter(Http::StreamFilterSharedPtr(instance));
    };
  }
};

static RegisterHttpFilterConfigFactory<TranscodingConfig> register_;

}  // namespace Configuration
}  // namespace Server
}  // namespace Envoy
