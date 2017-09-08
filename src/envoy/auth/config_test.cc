//
// Created by mtakigiku on 8/7/17.
//

#include "config.h"
//#include "config.cc"

#include "common/common/utility.h"
#include "test/test_common/utility.h"

namespace Envoy {
namespace Http {
namespace Auth {

class ConfigTest : public testing::Test {};

TEST_F(ConfigTest, ReadWholeFile) {
  std::string uri = "src/envoy/auth/integration_test/pubkey.jwk";
  std::string jwks = Util::ReadWholeFile(uri);
  printf("\n\tpubkey:\t%s\n\n", jwks.c_str());
  //  EXPECT_TRUE(0);
}

TEST_F(ConfigTest, GetContentFromUri) {
  std::string uri =
      "https://accounts.google.com/.well-known/openid-configuration";
  std::string content = Util::GetContentFromUri(uri);
  printf("\n\tcontent:\t%s\n\n", content.c_str());
  EXPECT_TRUE(0);
}
}
}
}