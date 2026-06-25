#pragma once

#include "catalog/rest/storage/iceberg_authorization.hpp"
#include "catalog/rest/storage/aws.hpp"

#include <chrono>
#include <mutex>

namespace duckdb {

class SIGV4Authorization : public IcebergAuthorization {
public:
	static constexpr const IcebergAuthorizationType TYPE = IcebergAuthorizationType::SIGV4;

public:
	SIGV4Authorization(AttachedDatabase &db);
	SIGV4Authorization(AttachedDatabase &db, const string &secret);

public:
	static unique_ptr<IcebergAuthorization> FromAttachOptions(AttachedDatabase &db, IcebergAttachOptions &input);
	unique_ptr<HTTPResponse> Request(RequestType request_type, ClientContext &context,
	                                 const IRCEndpointBuilder &endpoint_builder, HTTPHeaders &headers,
	                                 const string &data = "") override;

private:
	AWSInput CreateAWSInput(ClientContext &context, const IRCEndpointBuilder &endpoint_builder);

	//! Refresh the S3 secret if it has refresh_info and enough time has passed since the last refresh.
	//! Serialized by refresh_mutex so only one thread performs the refresh; concurrent callers skip.
	void MaybeRefreshSecret(ClientContext &context);

public:
	string secret;
	string region;
	//! Optional: override the AWS service name used for SigV4 signing, useful for self-hosted REST catalog services
	string sigv4_service;
	//! Optional: override the AWS region used for SigV4 signing, useful for non-AWS endpoints
	string sigv4_region;

public:
	//! Accessors for the shared refresh mutex and timestamp — used by TryRefreshCatalogSecret
	//! (in iceberg_table_information.cpp) which also calls CreateSecret on the same aws_secret.
	//! Both code paths must share the same mutex to prevent write-write conflicts.
	static std::mutex &GetRefreshMutex() { return refresh_mutex; }
	static std::chrono::steady_clock::time_point &GetLastRefreshTime() { return last_refresh_time; }

private:
	//! Guards concurrent secret refresh attempts across ALL code paths that call CreateSecret
	//! on aws_secret: SIGV4Authorization::MaybeRefreshSecret AND TryRefreshCatalogSecret.
	//! Must be static because multiple attached catalogs share the same aws_secret name.
	static std::mutex refresh_mutex;
	//! Time of last successful refresh (shared across all refresh paths)
	static std::chrono::steady_clock::time_point last_refresh_time;
	//! Minimum interval between refresh attempts (seconds). STS tokens last 900s minimum;
	//! refreshing every 300s gives comfortable headroom while avoiding the race.
	static constexpr int REFRESH_INTERVAL_SECONDS = 300;
};

} // namespace duckdb
