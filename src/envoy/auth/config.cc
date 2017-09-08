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

#include "config.h"

#include "common/filesystem/filesystem_impl.h"
#include "common/json/json_loader.h"
#include "envoy/json/json_object.h"
#include "envoy/upstream/cluster_manager.h"

#include "rapidjson/document.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace Envoy {
namespace Http {
namespace Auth {

IssuerInfo::~IssuerInfo() { Cancel(); }
void IssuerInfo::onSuccess(MessagePtr &&response) {
  std::string status = response->headers().Status()->value().c_str();
  if (status == "200") {
    ENVOY_LOG(debug, "IssuerInfo [cluster = {}]: {}", cluster_, __func__);
    std::string body;
    if (response->body()) {
      auto len = response->body()->length();
      body = std::string(static_cast<char *>(response->body()->linearize(len)),
                         len);
    } else {
      ENVOY_LOG(debug, "IssuerInfo [cluster = {}]: body is null", cluster_);
    }
    if (pkey_type_ == "pem") {
      pkey_->pkey_ = std::move(Pubkeys::CreateFromPem(body));
    } else if (pkey_type_ == "jwks") {
      pkey_->pkey_ = std::move(Pubkeys::CreateFromJwks(body));
    } else {
      PANIC("should not reach here");
    }
  } else {
    ENVOY_LOG(debug, "IssuerInfo [cluster = {}]: response status code {}",
              cluster_, status);
    pkey_->pkey_ = nullptr;
  }
  ProcessPendingCallbacks();
}
void IssuerInfo::onFailure(AsyncClient::FailureReason) {
  ENVOY_LOG(debug, "IssuerInfo [cluster = {}]: {}", cluster_, __func__);
  pkey_->pkey_ = nullptr;
  ProcessPendingCallbacks();
}

void IssuerInfo::Call() {
  ENVOY_LOG(debug, "IssuerInfo [cluster = {}]: {} {}", cluster_, __func__,
            uri_);
  // Example:
  // uri  = "https://example.com/certs"
  // pos  :          ^
  // pos1 :                     ^
  // host = "example.com"
  // path = "/certs"
  auto pos = uri_.find("://");
  pos = pos == std::string::npos ? 0 : pos + 3;  // Start position of host
  auto pos1 = uri_.find("/", pos);
  if (pos1 == std::string::npos) pos1 = uri_.length();
  std::string host = uri_.substr(pos, pos1 - pos);
  std::string path = "/" + uri_.substr(pos1 + 1);

  MessagePtr message(new RequestMessageImpl());
  message->headers().insertMethod().value().setReference(
      Http::Headers::get().MethodValues.Get);
  message->headers().insertPath().value(path);
  message->headers().insertHost().value(host);

  request_ = parent_.cm_.httpAsyncClientForCluster(cluster_info_->name())
                 .send(std::move(message), *this, timeout_);
}

void IssuerInfo::Cancel() { request_->cancel(); }

void IssuerInfo::ProcessPendingCallbacks() {
  pkey_->expiration_ = std::chrono::system_clock::now() + pkey_->valid_period_;
  {
    std::lock_guard<std::mutex> guard(mutex_pending_callbacks_);
    for (auto &callback : pending_callbacks_) {
      callback(pkey_->pkey_);
    }
    pending_callbacks_.clear();
  }
  {
    std::lock_guard<std::mutex> guard(mutex_state_);
    state_ = State::OK;
  }
}
void IssuerInfo::GetKeyAndDo(PubkeyCallBack callback) {
  if (pkey_->update_needed_) {
    {
      std::lock_guard<std::mutex> guard(mutex_state_);
      if (state_ == State::Calling) {
        std::lock_guard<std::mutex> guard(mutex_pending_callbacks_);
        pending_callbacks_.push_back(callback);
        return;
      }
      if (state_ == State::OK && pkey_->IsNotExpired()) {
        callback(pkey_->pkey_);
        return;
      }
      state_ = Calling;
    }
    {
      std::lock_guard<std::mutex> guard(mutex_pending_callbacks_);
      pending_callbacks_.push_back(callback);
    }
    Call();

  } else {
    callback(pkey_->pkey_);
  }
}

IssuerInfo::Pubkey::Pubkey(std::unique_ptr<Pubkeys> pkey)
    : update_needed_(false) {
  pkey_ = std::move(pkey);
}

IssuerInfo::Pubkey::Pubkey(std::chrono::duration<int> valid_period)
    : valid_period_(valid_period), update_needed_(true) {}

bool IssuerInfo::Pubkey::IsNotExpired() {
  return (!update_needed_) || (std::chrono::system_clock::now() < expiration_);
}

IssuerInfo::IssuerInfo(Json::Object *json, const JwtAuthConfig &parent)
    : parent_(parent), timeout_(Optional<std::chrono::milliseconds>()) {
  ENVOY_LOG(debug, "IssuerInfo: {}", __func__);
  // Check "name"
  name_ = json->getString("name", "");
  if (name_ == "") {
    ENVOY_LOG(debug, "IssuerInfo: Issuer name missing");
    failed_ = true;
    return;
  }
  // Check "pubkey"
  Json::ObjectSharedPtr json_pubkey;
  try {
    json_pubkey = json->getObject("pubkey");
  } catch (...) {
    ENVOY_LOG(debug, "IssuerInfo [name = {}]: Public key missing", name_);
    failed_ = true;
    return;
  }
  // Check "type"
  pkey_type_ = json_pubkey->getString("type", "");
  if (pkey_type_ == "") {
    ENVOY_LOG(debug, "IssuerInfo [name = {}]: Public key type missing", name_);
    failed_ = true;
    return;
  }
  if (pkey_type_ != "pem" && pkey_type_ != "jwks") {
    ENVOY_LOG(debug, "IssuerInfo [name = {}]: Public key type invalid", name_);
    failed_ = true;
    return;
  }
  // Check "value"
  std::string value = json_pubkey->getString("value", "");
  if (value != "") {
    //    pkey_ = std::unique_ptr<Pubkey>(new Pubkey());
    // Public key is written in this JSON.
    if (pkey_type_ == "pem") {
      pkey_ =
          std::unique_ptr<Pubkey>(new Pubkey(Pubkeys::CreateFromPem(value)));
    } else if (pkey_type_ == "jwks") {
      pkey_ =
          std::unique_ptr<Pubkey>(new Pubkey(Pubkeys::CreateFromJwks(value)));
    }
    return;
  }
  // Check "file"
  std::string path = json_pubkey->getString("file", "");
  if (path != "") {
    // Public key is loaded from the specified file.
    //    pkey_ = std::unique_ptr<Pubkey>(new Pubkey());
    if (pkey_type_ == "pem") {
      pkey_ = std::unique_ptr<Pubkey>(
          new Pubkey(Pubkeys::CreateFromPem(Filesystem::fileReadToEnd(path))));
    } else if (pkey_type_ == "jwks") {
      pkey_ = std::unique_ptr<Pubkey>(
          new Pubkey(Pubkeys::CreateFromJwks(Filesystem::fileReadToEnd(path))));
    }
    return;
  }
  // Check "uri" and "cluster"
  std::string uri = json_pubkey->getString("uri", "");
  std::string cluster = json_pubkey->getString("cluster", "");
  if (uri != "" && cluster != "") {
    // Public key will be loaded from the specified URI.
    uri_ = uri;
    cluster_ = cluster;
    cluster_info_ = parent_.cm_.get(cluster_)->info();
    pkey_ = std::unique_ptr<Pubkey>(
        new Pubkey(std::chrono::seconds(parent.pubkey_cache_expiration_sec_)));
    return;
  }

  // Public key not found
  ENVOY_LOG(debug, "IssuerInfo [name = {}]: Public key source missing", name_);
  failed_ = true;
}

/*
 * TODO: add test for config loading
 */
JwtAuthConfig::JwtAuthConfig(const Json::Object &config,
                             Server::Configuration::FactoryContext &context)
    : cm_(context.clusterManager()) {
  ENVOY_LOG(debug, "JwtAuthConfig: {}", __func__);
  std::string user_info_type_str =
      config.getString("userinfo_type", "payload_base64url");
  if (user_info_type_str == "payload") {
    user_info_type_ = UserInfoType::kPayload;
  } else if (user_info_type_str == "header_payload_base64url") {
    user_info_type_ = UserInfoType::kHeaderPayloadBase64Url;
  } else {
    user_info_type_ = UserInfoType::kPayloadBase64Url;
  }

  pubkey_cache_expiration_sec_ =
      config.getInteger("pubkey_cache_expiration_sec", 600);

  /*
   * TODO: audiences should be able to be specified for each issuer
   */
  // Empty array if key "audience" does not exist
  try {
    audiences_ = config.getStringArray("audience", true);
  } catch (...) {
    ENVOY_LOG(debug, "JwtAuthConfig: {}, Bad audiences", __func__);
  }

  // Load the issuers
  issuers_.clear();
  std::vector<Json::ObjectSharedPtr> issuer_jsons;
  try {
    issuer_jsons = config.getObjectArray("issuers");
  } catch (...) {
    ENVOY_LOG(debug, "JwtAuthConfig: {}, Bad issuers", __func__);
    abort();
  }
  for (auto issuer_json : issuer_jsons) {
    auto issuer = std::make_shared<IssuerInfo>(issuer_json.get(), *this);
    // If some error happened while loading in the constructor, this issuer will
    // be just skipped.
    if (!issuer->failed_) {
      issuers_.push_back(issuer);
    }
  }
}

}  // namespace Auth
}  // namespace Http
}  // namespace Envoy
