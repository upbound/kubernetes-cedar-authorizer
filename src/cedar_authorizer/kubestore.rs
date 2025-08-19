use std::collections::HashMap;
use std::{hash::Hash, sync::Arc};

use kube::api::ApiResource;
use kube::discovery::ApiCapabilities;
use kube::{discovery::ApiGroup, runtime::reflector, runtime::watcher};

use futures_util::{future::ready, StreamExt};
use kube::runtime::WatchStreamExt;
use tokio_util::sync::CancellationToken;

use serde::de::DeserializeOwned;
use std::fmt::Debug;
use std::marker::{Send, Sync};

pub trait KubeStore<K: 'static + Clone + reflector::Lookup>
where
    K::DynamicType: Eq + Hash + Clone + Default,
{
    fn get(&self, key: &reflector::ObjectRef<K>) -> Option<Arc<K>>;
}

pub struct KubeStoreImpl<K: 'static + Clone + reflector::Lookup>
where
    K::DynamicType: Eq + Hash + Clone + Default,
{
    store: reflector::Store<K>,
}

impl<K: 'static + Clone + reflector::Lookup> KubeStore<K> for KubeStoreImpl<K>
where
    K::DynamicType: Eq + Hash + Clone + Default,
{
    fn get(&self, key: &reflector::ObjectRef<K>) -> Option<Arc<K>> {
        self.store.get(key)
    }
}

impl<
        K: 'static
            + Clone
            + reflector::Lookup
            + kube::Resource
            + DeserializeOwned
            + Debug
            + Send
            + Sync,
    > KubeStoreImpl<K>
where
    <K as reflector::Lookup>::DynamicType: Eq + Hash + Clone + Default + Send + Sync,
{
    pub fn new(obj_client: kube::Api<K>, token: CancellationToken) -> Self {
        let (store, writer) = reflector::store();

        tokio::spawn(async move {
            let obj_watcher =
                watcher(obj_client, watcher::Config::default()).take_until(token.cancelled());
            reflector(writer, obj_watcher)
                .applied_objects()
                .for_each(|_| ready(()))
                .await;
        });

        Self { store }
    }
}

pub struct TestKubeStore<K: 'static + Clone + reflector::Lookup>
where
    K::DynamicType: Eq + Hash + Clone + Default,
{
    store: HashMap<reflector::ObjectRef<K>, Arc<K>>,
}

impl<K: 'static + Clone + reflector::Lookup> KubeStore<K> for TestKubeStore<K>
where
    K::DynamicType: Eq + Hash + Clone + Default,
{
    fn get(&self, key: &reflector::ObjectRef<K>) -> Option<Arc<K>> {
        self.store.get(key).cloned()
    }
}

impl<K: 'static + Clone + reflector::Lookup + kube::Resource> TestKubeStore<K>
where
    <K as reflector::Lookup>::DynamicType: Eq + Hash + Clone + Default,
{
    pub fn new(objects: Vec<K>) -> Self {
        let store = objects
            .into_iter()
            .map(|o| ((&o).into(), Arc::new(o)))
            .collect();
        Self { store }
    }
}
/*
pub trait KubeDiscovery<G: KubeApiGroup> {
    fn get_api_group(&self, group: &str) -> Option<&G>;
}

impl KubeDiscovery<ApiGroup> for kube::Discovery {
    fn get_api_group(&self, group: &str) -> Option<&ApiGroup> {
        self.get(group)
    }
}

pub(super) struct TestKubeDiscovery {
    api_groups: HashMap<String, TestKubeApiGroup>,
}

impl KubeDiscovery<TestKubeApiGroup> for TestKubeDiscovery {
    fn get_api_group(&self, group: &str) -> Option<&TestKubeApiGroup> {
        self.api_groups.get(group)
    }
}

impl TestKubeDiscovery {
    pub fn new(api_groups: Vec<TestKubeApiGroup>) -> Self {
        let api_groups = api_groups
            .into_iter()
            .map(|g| (g.name.clone(), g))
            .collect();
        Self { api_groups }
    }
}

pub trait KubeApiGroup {
    fn recommended_resources(&self) -> Vec<(ApiResource, ApiCapabilities)>;
}

impl KubeApiGroup for ApiGroup {
    fn recommended_resources(&self) -> Vec<(ApiResource, ApiCapabilities)> {
        let ver = self.preferred_version_or_latest();
        self.versioned_resources(ver)
    }
}

pub(super) struct TestKubeApiGroup {
    pub(super) name: String,
    pub(super) recommended_groups_resources: Vec<(ApiResource, ApiCapabilities)>,
}

impl KubeApiGroup for TestKubeApiGroup {
    fn recommended_resources(&self) -> Vec<(ApiResource, ApiCapabilities)> {
        self.recommended_groups_resources.clone()
    }
}
*/
