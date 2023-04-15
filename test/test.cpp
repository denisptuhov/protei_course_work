#include <gtest/gtest.h>
#include "../src/additional.h"
#include "../src/ethDevice.h"

TEST(ConvertingNeedTestSet, BELOW08) { 
    EXPECT_FALSE(isConvertKBtoMB(815));
    EXPECT_FALSE(isConvertKBtoMB(0));
}

TEST(ConvertingNeedTestSet, OVER08) { 
    EXPECT_TRUE(isConvertKBtoMB(820));
    EXPECT_TRUE(isConvertKBtoMB(1024));
}

TEST(CalculatingTestSet, CONVERT_FALSE) { 
    EXPECT_DOUBLE_EQ(1024, calculate_output_size(1024, 0));
}

TEST(CalculatingTestSet, CONVERT_TRUE) { 
    EXPECT_DOUBLE_EQ(1, calculate_output_size(1024, 1));
}


class HostInfoTest : public ::testing::Test {
protected:
    void SetUp() override {
        host = std::make_unique<hostInfo>();
    }

    void TearDown() override {
        host.reset();
    }

    std::unique_ptr<hostInfo> host;

};

TEST_F(HostInfoTest, MakeHostamePrettyTest) {
    host->set_hostname("google");
    host->make_hostname_pretty();
    EXPECT_EQ(host->get_hostname(), "google");

    host->set_hostname("google.com");
    host->make_hostname_pretty();
    EXPECT_EQ(host->get_hostname(), "google.com");

    host->set_hostname("sub.google.com");
    host->make_hostname_pretty();
    EXPECT_EQ(host->get_hostname(), "google.com");

    host->set_hostname("sub.sub.sub.google.com");
    host->make_hostname_pretty();
    EXPECT_EQ(host->get_hostname(), "google.com");
}

TEST_F(HostInfoTest, TestInsertHostDataIncomingPack) {
    host->insert_data(1024, 'i');

    EXPECT_EQ(host->get_count_in(), 1);
    EXPECT_FLOAT_EQ(host->get_in_package_size(), 1.0);
    EXPECT_EQ(host->get_count_out(), 0);
    EXPECT_EQ(host->get_out_package_size(), 0);
    EXPECT_EQ(host->get_total_package_size(), 1.0);
}

TEST_F(HostInfoTest, TestInsertHostDataOutgoingPack) {
    host->insert_data(2048, 'o');

    EXPECT_EQ(host->get_count_in(), 0);
    EXPECT_FLOAT_EQ(host->get_in_package_size(), 0);
    EXPECT_EQ(host->get_count_out(), 1);
    EXPECT_EQ(host->get_out_package_size(), 2.0);
    EXPECT_EQ(host->get_total_package_size(), 2.0);
}

 
int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}