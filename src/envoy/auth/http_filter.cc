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

#include <string>

namespace Envoy {
namespace Http {

const LowerCaseString& JwtVerificationFilter::AuthorizedHeaderKey() {
  static LowerCaseString* key = new LowerCaseString("Istio-Auth-UserInfo");
  return *key;
}

JwtVerificationFilter::JwtVerificationFilter(
    std::shared_ptr<Auth::JwtAuthConfig> config)
    : config_(config) {}

JwtVerificationFilter::~JwtVerificationFilter() {}

void JwtVerificationFilter::onDestroy() {
  ENVOY_LOG(debug, "Called JwtVerificationFilter : {}", __func__);
  state_ = Responded;
}

FilterHeadersStatus JwtVerificationFilter::decodeHeaders(HeaderMap& headers,
                                                         bool) {
  ENVOY_LOG(debug, "Called JwtVerificationFilter : {}", __func__);
  state_ = Calling;
  stopped_ = false;

  for (const auto& iss : config_->issuers_) {
    calling_issuers_set_.insert(iss->name_);
  }
  for (const auto& iss : config_->issuers_) {
    iss->GetKeyAndDo([&](std::shared_ptr<Auth::Pubkeys> pubkey) -> void {
      this->ReceivePubkey(headers, iss->name_, pubkey);
    });
  }

  if (state_ == Complete) {
    return FilterHeadersStatus::Continue;
  }
  ENVOY_LOG(debug, "Called JwtVerificationFilter : {} Stop", __func__);
  stopped_ = true;
  return FilterHeadersStatus::StopIteration;
}

FilterDataStatus JwtVerificationFilter::decodeData(Buffer::Instance&, bool) {
  ENVOY_LOG(debug, "Called JwtVerificationFilter : {}", __func__);
  if (state_ == Calling) {
    return FilterDataStatus::StopIterationAndBuffer;
  }
  return FilterDataStatus::Continue;
}

FilterTrailersStatus JwtVerificationFilter::decodeTrailers(HeaderMap&) {
  ENVOY_LOG(debug, "Called JwtVerificationFilter : {}", __func__);
  if (state_ == Calling) {
    return FilterTrailersStatus::StopIteration;
  }
  return FilterTrailersStatus::Continue;
}

void JwtVerificationFilter::setDecoderFilterCallbacks(
    StreamDecoderFilterCallbacks& callbacks) {
  ENVOY_LOG(debug, "Called JwtVerificationFilter : {}", __func__);
  decoder_callbacks_ = &callbacks;
}

void JwtVerificationFilter::ReceivePubkey(
    HeaderMap& headers, std::string issuer_name,
    std::shared_ptr<Auth::Pubkeys> pubkey) {
  ENVOY_LOG(debug, "Called JwtVerificationFilter : {} , issuer = {}", __func__,
            issuer_name);

  calling_issuers_set_.erase(issuer_name);
  pubkeys_copy_[issuer_name] = pubkey;

  // If it receive all responses, proceed to verification.
  if (calling_issuers_set_.empty()) {
    CompleteVerification(headers);
  }
}

/*
 * TODO: status as enum class
 */
std::string JwtVerificationFilter::Verify(HeaderMap& headers) {
  const HeaderEntry* entry = headers.get(kAuthorizationHeaderKey);
  if (!entry) {
    return "NO_AUTHORIZATION_HEADER";
  }
  const HeaderString& value = entry->value();
  if (strncmp(value.c_str(), kAuthorizationHeaderTokenPrefix.c_str(),
              kAuthorizationHeaderTokenPrefix.length()) != 0) {
    return "AUTHORIZATION_HEADER_BAD_FORMAT";
  }
  Auth::JwtVerifier jwt(value.c_str() +
                        kAuthorizationHeaderTokenPrefix.length());
  if (jwt.GetStatus() != Auth::Status::OK) {
    // Invalid JWT
    return Auth::StatusToString(jwt.GetStatus());
  }
  /*
   * TODO: check exp claim
   */

  for (const auto& iss : config_->issuers_) {
    std::shared_ptr<Auth::Pubkeys> pkey = pubkeys_copy_[iss->name_];
    if (!pkey || pkey->GetStatus() != Auth::Status::OK) {
      continue;
    }
    // Check "iss" claim.
    if (jwt.Iss() != iss->name_) {
      continue;
    }
    /*
     * TODO: check aud claim
     */

    if (jwt.Verify(*pkey)) {
      // verification succeeded
      /*
       * TODO: change what to add according to config_->user_info_type_
       */
      headers.addReferenceKey(AuthorizedHeaderKey(), jwt.PayloadStr());

      // Remove JWT from headers.
      headers.remove(kAuthorizationHeaderKey);
      return "OK";
    }
  }
  return "INVALID_SIGNATURE";
}

void JwtVerificationFilter::CompleteVerification(HeaderMap& headers) {
  ENVOY_LOG(debug, "Called JwtVerificationFilter : {}", __func__);
  if (state_ == Responded) {
    // This stream has been reset, abort the callback.
    return;
  }
  std::string status = Verify(headers);
  ENVOY_LOG(debug, "Verification status = {}", status);
  if (status != "OK") {
    // verification failed
    /*
     * TODO: detailed information on message body
     */
    Code code = Code(401);  // Unauthorized
    std::string message_body = "Verification Failed";
    Utility::sendLocalReply(*decoder_callbacks_, false, code, message_body);
    return;
  }

  state_ = Complete;
  if (stopped_) {
    decoder_callbacks_->continueDecoding();
  }
}

}  // Http
}  // Envoy
