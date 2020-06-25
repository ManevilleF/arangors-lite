#![allow(unused_imports)]
#![allow(unused_parens)]

use log::trace;
use pretty_assertions::assert_eq;
use serde_json::Value;

use arangors::collection::{CollectionPropertiesOptions, CollectionType};
use arangors::{ClientError, Connection, Document};
use common::{get_arangodb_host, get_normal_password, get_normal_user, test_setup};

pub mod common;

#[maybe_async::test(
    any(feature = "reqwest_blocking"),
    async(any(feature = "reqwest_async"), tokio::test),
    async(any(feature = "surf_async"), async_std::test)
)]
async fn test_get_collection() {
    test_setup();
    let host = get_arangodb_host();
    let user = get_normal_user();
    let password = get_normal_password();

    let conn = Connection::establish_jwt(&host, &user, &password)
        .await
        .unwrap();
    let database = conn.db("test_db").await.unwrap();
    let coll = database.accessible_collections().await;
    trace!("{:?}", coll);
    let coll = database.collection("test_collection").await;
    assert_eq!(coll.is_err(), false);
    let coll = database.collection("test_collection_non_exists").await;
    assert_eq!(coll.is_err(), true);
}

#[maybe_async::test(
    any(feature = "reqwest_blocking"),
    async(any(feature = "reqwest_async"), tokio::test),
    async(any(feature = "surf_async"), async_std::test)
)]
async fn test_create_and_drop_collection() {
    test_setup();
    let host = get_arangodb_host();
    let user = get_normal_user();
    let password = get_normal_password();

    let collection_name = "test_collection_create_and_drop";

    let conn = Connection::establish_jwt(&host, &user, &password)
        .await
        .unwrap();
    let mut database = conn.db("test_db").await.unwrap();

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), true);
    let coll = database.create_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
}

#[maybe_async::test(
    any(feature = "reqwest_blocking"),
    async(any(feature = "reqwest_async"), tokio::test),
    async(any(feature = "surf_async"), async_std::test)
)]
async fn test_get_properties() {
    test_setup();
    let host = get_arangodb_host();
    let user = get_normal_user();
    let password = get_normal_password();

    let collection_name = "test_collection_properties";

    let conn = Connection::establish_jwt(&host, &user, &password)
        .await
        .unwrap();
    let mut database = conn.db("test_db").await.unwrap();

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), true);

    let coll = database.create_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);

    let coll = database.collection(collection_name).await;
    assert_eq!(coll.is_err(), false);

    let properties = coll.unwrap().properties().await;
    assert_eq!(properties.is_err(), false);

    let result = properties.unwrap();

    assert_eq!(result.info.name, collection_name);
    #[cfg(rocksdb)]
    {
        assert_eq!(result.detail.cache_enabled, false);
    }
    #[cfg(mmfiles)]
    {
        assert_eq!(result.detail.is_volatile, false);
        assert_eq!(result.detail.do_compact, true);
    }
    assert_eq!(result.info.is_system, false);
    assert_eq!(result.detail.wait_for_sync, false);
    assert_eq!(result.detail.key_options.allow_user_keys, true);
    assert_eq!(
        result.detail.key_options.r#type,
        Some("traditional".to_string())
    );
    assert_eq!(result.detail.key_options.last_value, Some(0));
    assert_eq!(result.info.status, 3);
    assert_eq!(result.detail.write_concern, 1);

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
}

#[maybe_async::test(
    any(feature = "reqwest_blocking"),
    async(any(feature = "reqwest_async"), tokio::test),
    async(any(feature = "surf_async"), async_std::test)
)]
async fn test_get_document_count() {
    test_setup();
    let host = get_arangodb_host();
    let user = get_normal_user();
    let password = get_normal_password();

    let collection_name = "test_collection_count";

    let conn = Connection::establish_jwt(&host, &user, &password)
        .await
        .unwrap();
    let mut database = conn.db("test_db").await.unwrap();

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), true);

    let coll = database.create_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);

    let coll = database.collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
    let coll = coll.unwrap();
    let count = coll.document_count().await;

    let result = count.unwrap();
    assert_eq!(result.info.count, Some(0));
    assert_eq!(result.info.name, collection_name);
    #[cfg(rocksdb)]
    assert_eq!(result.detail.cache_enabled, false);
    assert_eq!(result.info.is_system, false);
    assert_eq!(result.detail.wait_for_sync, false);
    assert_eq!(result.detail.key_options.allow_user_keys, true);
    assert_eq!(
        result.detail.key_options.r#type,
        Some("traditional".to_string())
    );
    assert_eq!(result.detail.key_options.last_value, Some(0));
    assert_eq!(result.info.status, 3);
    assert_eq!(result.detail.write_concern, 1);

    let _query: Vec<Value> = database
        .aql_str(r#"INSERT {  "name": "test_user" } INTO test_collection_count"#)
        .await
        .unwrap();

    let updated_count = coll.document_count().await;
    let updated_result = updated_count.unwrap();
    assert_eq!(updated_result.info.count, Some(1));

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
}

#[maybe_async::test(
    any(feature = "reqwest_blocking"),
    async(any(feature = "reqwest_async"), tokio::test),
    async(any(feature = "surf_async"), async_std::test)
)]
async fn test_get_statistics() {
    test_setup();
    let host = get_arangodb_host();
    let user = get_normal_user();
    let password = get_normal_password();

    let collection_name = "test_collection_statistics";

    let conn = Connection::establish_jwt(&host, &user, &password)
        .await
        .unwrap();
    let mut database = conn.db("test_db").await.unwrap();

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), true, "drop collection");

    let coll = database.create_collection(collection_name).await;
    assert_eq!(coll.is_err(), false, "create collection");

    let coll = database.collection(collection_name).await.unwrap();
    let statistics = coll.statistics().await;

    let result = statistics.unwrap();
    assert_eq!(result.count, Some(0), "count");
    assert_eq!(result.info.name, collection_name);
    #[cfg(rocksdb)]
    assert_eq!(result.detail.cache_enabled, false);
    assert_eq!(result.info.is_system, false);
    assert_eq!(result.detail.wait_for_sync, false, "wait for sync");
    assert_eq!(
        result.detail.key_options.allow_user_keys, true,
        "allow user keys"
    );
    assert_eq!(
        result.detail.key_options.r#type,
        Some("traditional".to_string())
    );
    assert_eq!(result.detail.key_options.last_value, Some(0), "last value");
    assert_eq!(result.info.status, 3);
    assert_eq!(result.detail.write_concern, 1);

    assert_eq!(result.figures.indexes.count, Some(1));
    #[cfg(not(feature = "mmfiles"))]
    assert_eq!(result.figures.indexes.size, Some(0), "indexes size");

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), false, "fail to drop collection: {:?}", coll);
}

#[maybe_async::test(
    any(feature = "reqwest_blocking"),
    async(any(feature = "reqwest_async"), tokio::test),
    async(any(feature = "surf_async"), async_std::test)
)]
async fn test_get_revision_id() {
    test_setup();
    let host = get_arangodb_host();
    let user = get_normal_user();
    let password = get_normal_password();

    let collection_name = "test_collection_revision_id";

    let conn = Connection::establish_jwt(&host, &user, &password)
        .await
        .unwrap();
    let mut database = conn.db("test_db").await.unwrap();

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), true);

    let coll = database.create_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);

    let coll = database.collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
    let coll = coll.unwrap();
    let revision = coll.revision_id().await;

    let result = revision.unwrap();
    assert_eq!(result.revision, "0");
    assert_eq!(result.info.name, collection_name);
    #[cfg(rocksdb)]
    assert_eq!(result.detail.cache_enabled, false);
    assert_eq!(result.info.is_system, false);
    assert_eq!(result.detail.wait_for_sync, false);
    assert_eq!(result.detail.key_options.allow_user_keys, true);
    assert_eq!(
        result.detail.key_options.r#type,
        Some("traditional".to_string())
    );
    assert_eq!(result.detail.key_options.last_value, Some(0));
    assert_eq!(result.info.status, 3);
    assert_eq!(result.detail.write_concern, 1);

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
}

#[maybe_async::test(
    any(feature = "reqwest_blocking"),
    async(any(feature = "reqwest_async"), tokio::test),
    async(any(feature = "surf_async"), async_std::test)
)]
async fn test_get_checksum() {
    test_setup();
    let host = get_arangodb_host();
    let user = get_normal_user();
    let password = get_normal_password();

    let collection_name = "test_collection_checksum";

    let conn = Connection::establish_jwt(&host, &user, &password)
        .await
        .unwrap();
    let mut database = conn.db("test_db").await.unwrap();

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), true);

    let coll = database.create_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);

    let coll = database.collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
    let coll = coll.unwrap();
    let checksum = coll.checksum().await;

    let result = checksum.unwrap();
    assert_eq!(result.revision, "0");
    assert_eq!(result.info.name, collection_name);
    assert_eq!(result.info.is_system, false);
    assert_eq!(result.info.status, 3);
    assert_eq!(result.info.r#type, CollectionType::Document);
    assert_eq!(result.checksum, "0");
    assert_eq!(result.checksum.is_empty(), false);

    let checksum = coll.checksum_with_options(true, true).await;

    let updated_result = checksum.unwrap();
    assert_eq!(updated_result.revision, "0");
    assert_eq!(updated_result.info.name, collection_name);
    assert_eq!(updated_result.info.is_system, false);
    assert_eq!(updated_result.info.status, 3);
    assert_eq!(updated_result.info.r#type, CollectionType::Document);
    assert_eq!(updated_result.checksum, "0");
    assert_eq!(updated_result.checksum.is_empty(), false);

    let _query: Vec<Value> = database
        .aql_str(r#"INSERT {  "name": "test_user" } INTO test_collection_checksum"#)
        .await
        .unwrap();

    let checksum = coll.checksum().await;

    let updated_result = checksum.unwrap();

    let changed = if updated_result.revision != result.revision {
        true
    } else {
        false
    };
    assert_eq!(changed, true);
    assert_eq!(updated_result.info.name, collection_name);
    assert_eq!(updated_result.info.is_system, false);
    assert_eq!(updated_result.info.status, 3);
    assert_eq!(updated_result.info.r#type, CollectionType::Document);
    assert_eq!(updated_result.checksum.is_empty(), false);

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
}

#[maybe_async::test(
    any(feature = "reqwest_blocking"),
    async(any(feature = "reqwest_async"), tokio::test),
    async(any(feature = "surf_async"), async_std::test)
)]
async fn test_put_load() {
    test_setup();
    let host = get_arangodb_host();
    let user = get_normal_user();
    let password = get_normal_password();

    let collection_name = "test_collection_load";

    let conn = Connection::establish_jwt(&host, &user, &password)
        .await
        .unwrap();
    let mut database = conn.db("test_db").await.unwrap();

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), true);

    let coll = database.create_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);

    let coll = database.collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
    let coll = coll.unwrap();
    let load = coll.load(true).await;

    let result = load.unwrap();

    assert_eq!(result.name, collection_name);
    assert_eq!(result.is_system, false);
    assert_eq!(result.count, Some(0));
    assert_eq!(result.status, 3);
    assert_eq!(result.r#type, CollectionType::Document);

    let load = coll.load(false).await;

    let updated_result = load.unwrap();
    assert_eq!(updated_result.name, collection_name);
    assert_eq!(updated_result.is_system, false);
    assert_eq!(updated_result.count, None);
    assert_eq!(updated_result.status, 3);
    assert_eq!(updated_result.r#type, CollectionType::Document);

    let _query: Vec<Value> = database
        .aql_str(r#"INSERT {  "name": "test_user" } INTO test_collection_load"#)
        .await
        .unwrap();

    let load = coll.load(true).await;

    let updated_result = load.unwrap();
    assert_eq!(updated_result.name, collection_name);
    assert_eq!(updated_result.is_system, false);
    assert_eq!(updated_result.count, Some(1));
    assert_eq!(updated_result.status, 3);
    assert_eq!(updated_result.r#type, CollectionType::Document);

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
}

#[maybe_async::test(
    any(feature = "reqwest_blocking"),
    async(any(feature = "reqwest_async"), tokio::test),
    async(any(feature = "surf_async"), async_std::test)
)]
async fn test_put_unload() {
    test_setup();
    let host = get_arangodb_host();
    let user = get_normal_user();
    let password = get_normal_password();

    let collection_name = "test_collection_unload";

    let conn = Connection::establish_jwt(&host, &user, &password)
        .await
        .unwrap();
    let mut database = conn.db("test_db").await.unwrap();

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), true);

    let coll = database.create_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);

    let coll = database.collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
    let coll = coll.unwrap();
    let unload = coll.unload().await;

    let result = unload.unwrap();

    assert_eq!(result.name, collection_name);
    assert_eq!(result.is_system, false);
    assert_eq!(result.count, None);
    assert_eq!(result.status, 2);
    assert_eq!(result.r#type, CollectionType::Document);

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
}

#[maybe_async::test(
    any(feature = "reqwest_blocking"),
    async(any(feature = "reqwest_async"), tokio::test),
    async(any(feature = "surf_async"), async_std::test)
)]
async fn test_put_load_indexes_into_memory() {
    test_setup();
    let host = get_arangodb_host();
    let user = get_normal_user();
    let password = get_normal_password();

    let collection_name = "test_collection_load_indexes_into_memory";

    let conn = Connection::establish_jwt(&host, &user, &password)
        .await
        .unwrap();
    let mut database = conn.db("test_db").await.unwrap();

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), true);

    let coll = database.create_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);

    let coll = database.collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
    let coll = coll.unwrap();
    let load_index = coll.load_indexes().await;

    let result = load_index.unwrap();
    assert_eq!(result, true);

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
}

#[maybe_async::test(
    any(feature = "reqwest_blocking"),
    async(any(feature = "reqwest_async"), tokio::test),
    async(any(feature = "surf_async"), async_std::test)
)]
async fn test_put_changes_properties() {
    test_setup();
    let host = get_arangodb_host();
    let user = get_normal_user();
    let password = get_normal_password();

    let collection_name = "test_collection_changes_properties";

    let conn = Connection::establish_jwt(&host, &user, &password)
        .await
        .unwrap();
    let mut database = conn.db("test_db").await.unwrap();

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), true);

    let coll = database.create_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);

    let coll = database.collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
    let coll = coll.unwrap();

    let updated_properties = coll
        .change_properties(CollectionPropertiesOptions {
            wait_for_sync: Some(true),
        })
        .await;

    let result = updated_properties.unwrap();
    assert_eq!(result.info.name, collection_name);
    #[cfg(rocksdb)]
    assert_eq!(result.detail.cache_enabled, false);
    assert_eq!(result.info.is_system, false);
    assert_eq!(result.detail.wait_for_sync, true);
    assert_eq!(result.detail.key_options.allow_user_keys, true);
    assert_eq!(
        result.detail.key_options.r#type,
        Some("traditional".to_string())
    );
    assert_eq!(result.detail.key_options.last_value, Some(0));
    assert_eq!(result.info.status, 3);
    assert_eq!(result.detail.write_concern, 1);

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
}

#[maybe_async::test(
    any(feature = "reqwest_blocking"),
    async(any(feature = "reqwest_async"), tokio::test),
    async(any(feature = "surf_async"), async_std::test)
)]
async fn test_put_rename() {
    test_setup();
    let host = get_arangodb_host();
    let user = get_normal_user();
    let password = get_normal_password();

    let collection_name = "test_collection_rename";

    let conn = Connection::establish_jwt(&host, &user, &password)
        .await
        .unwrap();
    let mut database = conn.db("test_db").await.unwrap();

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), true);

    let coll = database.create_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);

    let coll = database.collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
    let coll = coll.unwrap();
    let new_name = "test_collection_renamed_2";
    let renamed = coll.rename(new_name).await;

    let result = renamed.unwrap();
    assert_eq!(result.name, new_name);
    assert_eq!(result.is_system, false);
    assert_eq!(result.status, 3);
    assert_eq!(result.r#type, CollectionType::Document);

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), true);
    let coll = database.drop_collection(new_name).await;
    assert_eq!(coll.is_err(), false);
}

#[cfg(feature = "rocksdb")]
#[maybe_async::test(
    any(feature = "reqwest_blocking"),
    async(any(feature = "reqwest_async"), tokio::test),
    async(any(feature = "surf_async"), async_std::test)
)]
async fn test_put_recalculate() {
    test_setup();
    let host = get_arangodb_host();
    let user = get_normal_user();
    let password = get_normal_password();

    let collection_name = "test_collection_recalculate";

    let conn = Connection::establish_jwt(&host, &user, &password)
        .await
        .unwrap();
    let mut database = conn.db("test_db").await.unwrap();

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), true);

    let coll = database.create_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);

    let coll = database.collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
    let coll = coll.unwrap();
    let recalculate = coll.recalculate_count().await;

    let result = recalculate.unwrap();
    assert_eq!(result, true);

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
}

#[cfg(any(feature = "mmfiles"))]
#[maybe_async::test(
    any(feature = "reqwest_blocking"),
    async(any(feature = "reqwest_async"), tokio::test),
    async(any(feature = "surf_async"), async_std::test)
)]
async fn test_put_rotate_journal() {
    test_setup();
    let host = get_arangodb_host();
    let user = get_normal_user();
    let password = get_normal_password();

    let collection_name = "test_collection_rotate_journal";

    let conn = Connection::establish_jwt(&host, &user, &password)
        .await
        .unwrap();
    let mut database = conn.db("test_db").await.unwrap();

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), true);

    let coll = database.create_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);

    let coll = database.collection(collection_name).await.unwrap();

    let rotate = coll.rotate_journal().await;

    // TODO got no journal error, don't know how to create a journal
    assert_eq!(rotate.is_err(), true, "succeed rotating journal");
    if let ClientError::Arango(error) = rotate.unwrap_err() {
        assert_eq!(
            error.code(),
            400,
            "Should be no journal, but now it's: {}",
            error.message()
        )
    }

    // assert_eq!(rotate.is_ok(), true, "fail to rotate journal: {:?}", rotate);
    // let result = rotate.unwrap();
    // assert_eq!(result, true, "rotate result should be true");

    let coll = database.drop_collection(collection_name).await;
    assert_eq!(coll.is_err(), false);
}
