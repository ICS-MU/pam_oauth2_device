#include <string>

#include "gtest/gtest.h"
#include "pam_oauth2_device.hpp"

#define DEVICE_ENDPOINT "http://localhost:8042/devicecode"
#define TOKEN_ENDPOINT "http://localhost:8042/token"
#define USERINFO_ENDPOINT "http://localhost:8042/userinfo"
#define USERNAME_ATTRIBUTE "preferred_username"
#define CLIENT_ID "client_id"
#define CLIENT_SECRET "NDVmODY1ZDczMGIyMTM1MWFlYWM2NmYw"
#define SCOPE "openid profile"
#define USER_CODE "QWERTY"
#define DEVICE_CODE "e1e9b7be-e720-467e-bbe1-5c382356e4a9"
#define ACCESS_TOKEN "ZjBhNTQxYzEzMGQwNWU1OWUxMDhkMTM5"
#define VERIFICATION_URL "http://localhost:8042/oidc/device"

namespace {

TEST(PamTest, Device) {
  DeviceAuthResponse response;
  make_authorization_request(CLIENT_ID, CLIENT_SECRET, SCOPE, DEVICE_ENDPOINT,
                             false, &response);
  EXPECT_EQ(response.user_code, USER_CODE);
  EXPECT_EQ(response.device_code, DEVICE_CODE);
  EXPECT_EQ(response.verification_uri, VERIFICATION_URL);
  EXPECT_EQ(response.verification_uri_complete,
            std::string(VERIFICATION_URL) + "?user_code=" + DEVICE_CODE);
}

TEST(PamTest, Token) {
  std::string token;
  poll_for_token(CLIENT_ID, CLIENT_SECRET, TOKEN_ENDPOINT, DEVICE_CODE, &token);
  EXPECT_EQ(token, ACCESS_TOKEN);
}

TEST(PamTest, Userinfo) {
  Userinfo userinfo;
  get_userinfo(USERINFO_ENDPOINT, ACCESS_TOKEN, USERNAME_ATTRIBUTE, &userinfo);
  EXPECT_EQ(userinfo.sub, "YzQ4YWIzMzJhZjc5OWFkMzgwNmEwM2M5");
  EXPECT_EQ(userinfo.username, "jdoe");
  EXPECT_EQ(userinfo.name, "Joe Doe");
}

}  // namespace
