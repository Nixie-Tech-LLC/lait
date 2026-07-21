//! The product's adoption of the orbital lifecycle.
//!
//! This is the S5c seam: the root application hosting a real, product-shaped
//! [`World`] over LAIT-owned Body operations and driving it through the public
//! `runtime` API — the same surface any consumer uses, with no privileged path.
//! It does **not** replace the existing daemon's catalog/issue Loro documents;
//! it establishes the dependency edge and proves the product can form Spaces,
//! host a World, dock Sessions, and durably commit through Replica/Fabric.
//!
//! Issues are modeled as **atomic Bodies**: each issue is one canonical JSON
//! value replaced per transaction. `submit` decodes a [`IssueCommand`], reads
//! the current issue from the committed snapshot when it needs to (edit /
//! comment), and stages a single atomic replacement; `query` returns the
//! committed issue JSON. The collaborative-CRDT issue model (per-field
//! convergence) is a later migration behind this same World contract.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

// `::replica` disambiguates the external crate from this product's own
// `crate::replica` module.
use ::replica::body::{BodyOp, BodySchema, MutationModel};
use ::replica::frontier::ReplicaFrontier;
use ::replica::ids::{BodyId, BodyKey, EncodingId, SchemaId, WorldId};
use runtime::{
    Runtime, RuntimeBuilder, World, WorldContext, WorldEffect, WorldError, WorldIntent,
    WorldLimits, WorldProjection, WorldQuery, WorldRegistration, WorldVersion,
};

/// The product World's reverse-domain identity.
pub const ISSUES_WORLD_ID: &str = "com.nixiesoftware.issues";
/// The issue schema id.
pub const ISSUE_SCHEMA: &str = "issue";

/// A command a caller submits to the Issues World.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IssueCommand {
    /// Create (or overwrite) an issue with a title and optional body.
    Create {
        id: String,
        title: String,
        #[serde(default)]
        body: String,
    },
    /// Edit an existing issue's title and/or body (read-modify-write).
    Edit {
        id: String,
        #[serde(default)]
        title: Option<String>,
        #[serde(default)]
        body: Option<String>,
    },
    /// Append a comment to an existing issue.
    Comment { id: String, text: String },
}

/// A query to the Issues World.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "q", rename_all = "snake_case")]
pub enum IssueQuery {
    /// Get one issue's current state.
    Get { id: String },
}

/// The canonical stored form of an issue.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IssueState {
    pub id: String,
    pub title: String,
    pub body: String,
    pub comments: Vec<String>,
}

/// The product's Issues World: a small but genuine adopter of the World
/// contract.
pub struct IssuesWorld {
    id: WorldId,
    schemas: Vec<BodySchema>,
}

impl Default for IssuesWorld {
    fn default() -> Self {
        Self::new()
    }
}

impl IssuesWorld {
    pub fn new() -> Self {
        Self {
            id: WorldId::parse(ISSUES_WORLD_ID).expect("valid world id"),
            schemas: vec![BodySchema {
                id: SchemaId::parse(ISSUE_SCHEMA).expect("valid schema id"),
                version: 1,
                encoding: EncodingId::parse("json").expect("valid encoding id"),
                mutation: MutationModel::Atomic,
                readable_predecessors: vec![],
            }],
        }
    }

    /// The stable Body key for an issue id (128 bits of BLAKE3 over the id).
    fn body_key(&self, issue_id: &str) -> BodyKey {
        let digest = blake3::hash(issue_id.as_bytes());
        let mut raw = [0u8; 16];
        raw.copy_from_slice(&digest.as_bytes()[..16]);
        BodyKey::new(self.id.clone(), BodyId::from_bytes(raw))
    }

    fn read_issue(&self, ctx: &WorldContext<'_>, issue_id: &str) -> Option<IssueState> {
        ctx.read_body(&self.body_key(issue_id))
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    fn replace(&self, issue: &IssueState) -> Result<WorldEffect, WorldError> {
        let key = self.body_key(&issue.id);
        let value = serde_json::to_vec(issue).map_err(|_| WorldError::InvalidRequest)?;
        Ok(WorldEffect {
            operations: vec![(
                key.clone(),
                BodyOp::ReplaceAtomic {
                    value: value.clone(),
                },
            )],
            scopes: vec![key],
            effect: value,
        })
    }
}

impl World for IssuesWorld {
    fn id(&self) -> WorldId {
        self.id.clone()
    }

    fn schemas(&self) -> &[BodySchema] {
        &self.schemas
    }

    fn submit(
        &self,
        ctx: &mut WorldContext<'_>,
        intent: WorldIntent,
    ) -> Result<WorldEffect, WorldError> {
        if intent.schema.as_str() != ISSUE_SCHEMA {
            return Err(WorldError::UnsupportedSchema);
        }
        let cmd: IssueCommand =
            serde_json::from_slice(&intent.payload).map_err(|_| WorldError::InvalidRequest)?;
        match cmd {
            IssueCommand::Create { id, title, body } => {
                let issue = IssueState {
                    id,
                    title,
                    body,
                    comments: Vec::new(),
                };
                self.replace(&issue)
            }
            IssueCommand::Edit { id, title, body } => {
                let mut issue = self
                    .read_issue(&*ctx, &id)
                    .ok_or(WorldError::InvalidRequest)?;
                if let Some(t) = title {
                    issue.title = t;
                }
                if let Some(b) = body {
                    issue.body = b;
                }
                self.replace(&issue)
            }
            IssueCommand::Comment { id, text } => {
                let mut issue = self
                    .read_issue(&*ctx, &id)
                    .ok_or(WorldError::InvalidRequest)?;
                issue.comments.push(text);
                self.replace(&issue)
            }
        }
    }

    fn query(
        &self,
        ctx: &WorldContext<'_>,
        query: WorldQuery,
    ) -> Result<WorldProjection, WorldError> {
        if query.schema.as_str() != ISSUE_SCHEMA {
            return Err(WorldError::UnsupportedSchema);
        }
        let q: IssueQuery =
            serde_json::from_slice(&query.payload).map_err(|_| WorldError::InvalidRequest)?;
        let IssueQuery::Get { id } = q;
        let issue = self.read_issue(ctx, &id).unwrap_or_default();
        let bytes = serde_json::to_vec(&issue).map_err(|_| WorldError::InvalidRequest)?;
        Ok(WorldProjection {
            schema: SchemaId::parse(ISSUE_SCHEMA).expect("schema"),
            schema_version: 1,
            bytes,
            frontier: ReplicaFrontier::EMPTY,
        })
    }
}

/// Open a product Runtime rooted at `home`, hosting the [`IssuesWorld`]. This is
/// the product's entry into the orbital lifecycle: the returned [`Runtime`] can
/// `form_space`, `orbit`, activate Stations, and dock Sessions to the Issues
/// World — all through the public API.
pub fn open_orbital_runtime(home: impl Into<PathBuf>) -> Runtime {
    let world = IssuesWorld::new();
    let registration = WorldRegistration {
        id: world.id(),
        implementation_version: WorldVersion(1),
        schemas: world.schemas().to_vec(),
        limits: WorldLimits::default(),
    };
    let registry = RuntimeBuilder::new()
        .register(registration, Arc::new(world))
        .build()
        .expect("issues world registers");
    Runtime::open(home, registry)
}
