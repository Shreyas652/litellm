//! A JWT caller's team, membership and user as the auth cache holds them, as far as the native
//! host reads them. Each entry is taken apart by name, so a field added to it does not compile
//! here until it is honored or named as one the native app has no counterpart for. Nothing here
//! charges or limits a team, a member or a user, so a row that holds a limit, a budget, a model
//! list or anything Python applies after auth is declined, naming the field.

use litellm_gateway_auth_core::{
    authz::ModelList,
    identity::jwt::{Team, User},
    record::{MembershipRecord, TeamRecord, UserRecord},
    routes::passthrough::PassthroughGrants,
};
use litellm_python_compat::Value;
use litellm_redis_store::auth_cache::{Bag, TeamEntry, TeamMembershipEntry, UserEntry};

use super::key::Carried;

/// The `metadata` key SCIM sets to `False` on a user it deactivated.
const SCIM_ACTIVE: &str = "scim_active";

/// The fields that describe a team rather than govern its calls, its roster and spend included,
/// are read for nothing. `models` is the team's layer of the model rule, and a list with an entry
/// that rule does not read declines. Every other field that holds something is a limit, a budget,
/// a grant or a setting Python applies after auth.
pub(super) fn team(team: &TeamEntry) -> Result<Team<TeamRecord>, &'static str> {
    let TeamEntry {
        team_alias,
        team_id,
        organization_id,
        admins: _,
        members: _,
        members_with_roles,
        team_member_permissions: _,
        metadata,
        tpm_limit,
        rpm_limit,
        tpd_limit,
        max_budget,
        soft_budget,
        budget_duration,
        budget_limits,
        models,
        blocked,
        router_settings,
        access_group_ids,
        default_team_member_models,
        spend: _,
        max_parallel_requests,
        budget_reset_at,
        model_id,
        model_spend: _,
        model_max_budget,
        policies,
        allow_team_guardrail_config,
        litellm_model_table,
        object_permission,
        object_permission_id,
        updated_at: _,
        created_at: _,
        last_refreshed_at: _,
        unread,
    } = team;
    let unread = &newer(unread);
    let unread_models = matches!(ModelList::read(models), ModelList::Unread);
    let held = unread_models.then_some("models").or(carried![
        organization_id,
        metadata,
        tpm_limit,
        rpm_limit,
        tpd_limit,
        max_budget,
        soft_budget,
        budget_duration,
        budget_limits,
        blocked,
        router_settings,
        access_group_ids,
        default_team_member_models,
        max_parallel_requests,
        budget_reset_at,
        model_id,
        model_max_budget,
        policies,
        allow_team_guardrail_config,
        litellm_model_table,
        object_permission,
        object_permission_id,
        unread,
    ]);
    if let Some(field) = held {
        return Err(field);
    }
    Ok(Team {
        team_id: team_id.clone(),
        models: Some(models.clone()),
        passthrough: PassthroughGrants::default(),
        members: members_with_roles
            .iter()
            .filter_map(|member| member.user_id.clone())
            .collect(),
        row: TeamRecord {
            team_id: team_id.clone(),
            team_alias: team_alias.clone(),
            models: models.clone(),
        },
    })
}

/// A membership with a budget of its own is one the team member budget check reads.
pub(super) fn membership(
    membership: &TeamMembershipEntry,
) -> Result<MembershipRecord, &'static str> {
    let TeamMembershipEntry {
        user_id,
        team_id,
        budget_id,
        spend: _,
        total_spend: _,
        rollover_credit,
        litellm_budget_table,
        unread,
    } = membership;
    let unread = &newer(unread);
    if let Some(field) = carried![budget_id, rollover_credit, litellm_budget_table, unread] {
        return Err(field);
    }
    Ok(MembershipRecord {
        user_id: user_id.clone(),
        team_id: team_id.clone(),
    })
}

/// The user's id, alias, email, role, teams and SCIM state are what the core reads. The fields
/// that describe the row or its sign-in are read for nothing, and every other field that holds
/// something is a limit, a budget, a grant or an owner Python reads after auth.
pub(super) fn user(user: &UserEntry) -> Result<User<UserRecord>, &'static str> {
    let UserEntry {
        user_id,
        user_alias,
        team_id,
        sso_user_id: _,
        organization_id,
        object_permission_id,
        password_reset_required: _,
        last_breach_check_at: _,
        teams,
        user_role,
        max_budget,
        rollover_max_budget,
        rollover_credit,
        budget_limits,
        spend: _,
        user_email,
        models,
        metadata,
        max_parallel_requests,
        tpm_limit,
        rpm_limit,
        budget_duration,
        budget_reset_at,
        allowed_cache_controls,
        policies,
        model_spend: _,
        model_max_budget,
        created_at: _,
        updated_at: _,
        organization_memberships,
        object_permission,
        unread,
    } = user;
    let unread = &newer(unread);
    let deactivated = scim_deactivated(metadata.as_ref()).ok_or("metadata")?;
    let held = carried![
        team_id,
        organization_id,
        object_permission_id,
        max_budget,
        rollover_max_budget,
        rollover_credit,
        budget_limits,
        models,
        max_parallel_requests,
        tpm_limit,
        rpm_limit,
        budget_duration,
        budget_reset_at,
        allowed_cache_controls,
        policies,
        model_max_budget,
        organization_memberships,
        object_permission,
        unread,
    ];
    if let Some(field) = held {
        return Err(field);
    }
    Ok(User {
        user_id: user_id.clone(),
        user_email: user_email.clone(),
        user_role: user_role.clone(),
        teams: teams.clone(),
        deactivated,
        row: UserRecord {
            user_id: user_id.clone(),
            user_alias: user_alias.clone(),
        },
    })
}

/// Whether a field this build does not name, which a newer pod wrote, holds something.
fn newer(unread: &[(String, Value)]) -> bool {
    unread.iter().any(|(_, value)| value.is_carried())
}

/// Whether SCIM deactivated the user, as `metadata.get("scim_active") is False` reads it. `None`
/// when the metadata holds anything else.
fn scim_deactivated(metadata: Option<&Bag>) -> Option<bool> {
    let entries = metadata.map(Bag::entries).unwrap_or_default();
    match entries {
        [] => Some(false),
        [(Value::Str(key), active)] if key == SCIM_ACTIVE => {
            Some(matches!(active, Value::Bool(false)))
        }
        _ => None,
    }
}
