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

#include "http_filter.h"
#include "config.h"
#include "jwt.h"

#include "common/http/message_impl.h"
#include "common/http/utility.h"
#include "envoy/http/async_client.h"
#include "server/config/network/http_connection_manager.h"

#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <string>

namespace Envoy {
namespace Http {

// namespace {
//
// std::string JsonToString(rapidjson::Document* d) {
//  rapidjson::StringBuffer buffer;
//  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
//  d->Accept(writer);
//  return buffer.GetString();
//}
//
//}  // namespace

const LowerCaseString& JwtVerificationFilter::AuthorizedHeaderKey() {
  static LowerCaseString* key = new LowerCaseString("Istio-Auth-UserInfo");
  return *key;
}

JwtVerificationFilter::JwtVerificationFilter(
    std::shared_ptr<Auth::JwtAuthConfig> config)
    : config_(config) {}

JwtVerificationFilter::~JwtVerificationFilter() {}

void JwtVerificationFilter::onDestroy() {}

FilterHeadersStatus JwtVerificationFilter::decodeHeaders(HeaderMap& headers,
                                                         bool) {
  state_ = Calling;
  stopped_ = false;

  /*
   * TODO: update cached public key regularly
   */

  // list up issuers whose public key should be fetched
  for (const auto& iss : config_->issuers_) {
    if (!iss->failed_ && !iss->loaded_) {
      calling_issuers_[iss->name_] = iss;
    }
  }
  // send HTTP requests to fetch public keys
  if (!calling_issuers_.empty()) {
    for (const auto& iss : config_->issuers_) {
      if (iss->failed_ || iss->loaded_) {
        continue;
      }
      iss->async_client_cb_ = std::unique_ptr<Auth::AsyncClientCallbacks>(
          new Auth::AsyncClientCallbacks(
              config_->cm_, iss->cluster_,
              [&](bool succeed, const std::string& pubkey) -> void {
                this->ReceivePubkey(headers, iss->name_, succeed, pubkey);
              }));

      iss->async_client_cb_->Call(iss->uri_);
    }
  } else {
    // If we do not need to fetch any public keys, just proceed to verification.
    CompleteVerification(headers);
  }

  if (state_ == Complete) {
    return FilterHeadersStatus::Continue;
  }
  stopped_ = true;
  return FilterHeadersStatus::StopIteration;
}

FilterDataStatus JwtVerificationFilter::decodeData(Buffer::Instance&, bool) {
  if (state_ == Calling) {
    return FilterDataStatus::StopIterationAndBuffer;
  }
  return FilterDataStatus::Continue;
}

FilterTrailersStatus JwtVerificationFilter::decodeTrailers(HeaderMap&) {
  if (state_ == Calling) {
    return FilterTrailersStatus::StopIteration;
  }
  return FilterTrailersStatus::Continue;
}

void JwtVerificationFilter::setDecoderFilterCallbacks(
    StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}

void JwtVerificationFilter::ReceivePubkey(HeaderMap& headers,
                                          std::string issuer_name, bool succeed,
                                          const std::string& pubkey) {
  auto iss_it = calling_issuers_.find(issuer_name);
  auto& iss = iss_it->second;
  iss->failed_ = !succeed;
  if (succeed) {
    iss->pkey_ = pubkey;
  }
  iss->loaded_ = true;
  calling_issuers_.erase(iss_it);

  // if receive all responses, proceed to verification
  if (calling_issuers_.empty()) {
    CompleteVerification(headers);
  }
}

void JwtVerificationFilter::CompleteVerification(HeaderMap& headers) {
  std::string fail_body = "";
  const HeaderEntry* entry = headers.get(kAuthorizationHeaderKey);
  if (entry) {
    const HeaderString& value = entry->value();
    if (strncmp(value.c_str(), kAuthorizationHeaderTokenPrefix.c_str(),
                kAuthorizationHeaderTokenPrefix.length()) == 0) {
      std::string jwt(value.c_str() + kAuthorizationHeaderTokenPrefix.length());

      Auth::JwtVerifier v(jwt);
      for (const auto& iss : config_->issuers_) {
        if (iss->failed_) {
          continue;
        }

        /*
         * TODO: update according to change of JWT lib interface
         */
        // verifying and decoding JWT
        //        std::unique_ptr<rapidjson::Document> payload;
        std::unique_ptr<Auth::Pubkeys> pkey;
        if (iss->pkey_type_ == "pem") {
          pkey = Auth::Pubkeys::ParseFromPem(iss->pkey_);
          //          payload = Auth::Jwt::Decode(jwt, iss->pkey_);
        } else if (iss->pkey_type_ == "jwks") {
          pkey = Auth::Pubkeys::ParseFromJwks(iss->pkey_);
          //          payload = Auth::Jwt::DecodeWithJwk(jwt, iss->pkey_);
        }

        if (v.Verify(*pkey)) {
          // verification succeeded
          Json::ObjectSharedPtr payload = v.Payload();

          // Check the issuer's name.
          std::string jwt_iss = payload->getString("iss", "");

          if (jwt_iss == iss->name_) {
            /*
             * TODO: check exp claim
             */
            std::string aud = v.Aud();
            if (config_->IsValidAudience(aud)) {
              /*
               * TODO: replace appropriately
               */
              std::string str_to_add;
              switch (config_->user_info_type_) {
                case Auth::JwtAuthConfig::UserInfoType::kPayload:
                  str_to_add = v.PayloadStr();
                  break;
                case Auth::JwtAuthConfig::UserInfoType::kPayloadBase64Url:
                  str_to_add = v.PayloadStrBase64Url();
                  break;
                case Auth::JwtAuthConfig::UserInfoType::kHeaderPayloadBase64Url:
                  str_to_add =
                      v.HeaderStrBase64Url() + "." + v.PayloadStrBase64Url();
              }
              headers.addReferenceKey(AuthorizedHeaderKey(), str_to_add);

              // Remove JWT from headers.
              headers.remove(kAuthorizationHeaderKey);
              goto end;
            } else {
              fail_body = Auth::StatusToString(Auth::Status::BAD_AUDIENCE);
            }
          }
        }
      }
      fail_body = Auth::StatusToString(v.GetStatus());
    } else {
      fail_body = Auth::StatusToString(Auth::Status::NO_AUTHORIZATION_HEADER);
    }
  } else {
    fail_body = Auth::StatusToString(Auth::Status::NO_AUTHORIZATION_HEADER);
  }

  // verification failed
  {
    /*
     * TODO: detailed information on message body
     */
    Code code = Code(401);  // Unauthorized
    std::string message_body = fail_body;
    Utility::sendLocalReply(*decoder_callbacks_, false, code, message_body);
    return;
  }

end:
  state_ = Complete;
  if (stopped_) {
    decoder_callbacks_->continueDecoding();
  }
}

}  // Http
}  // Envoy
