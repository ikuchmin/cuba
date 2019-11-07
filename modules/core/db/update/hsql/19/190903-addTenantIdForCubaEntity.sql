alter table SYS_FILE add SYS_TENANT_ID varchar(255)^
alter table SYS_SCHEDULED_TASK add SYS_TENANT_ID varchar(255)^
alter table SYS_SCHEDULED_EXECUTION add SYS_TENANT_ID varchar(255)^
alter table SEC_ROLE add SYS_TENANT_ID varchar(255)^
alter table SEC_GROUP add SYS_TENANT_ID varchar(255)^
alter table SEC_GROUP_HIERARCHY add SYS_TENANT_ID varchar(255)^
alter table SEC_USER add SYS_TENANT_ID varchar(255)^
alter table SEC_USER_ROLE add SYS_TENANT_ID varchar(255)^
alter table SEC_PERMISSION add SYS_TENANT_ID varchar(255)^
alter table SEC_CONSTRAINT add SYS_TENANT_ID varchar(255)^
alter table SEC_LOCALIZED_CONSTRAINT_MSG add SYS_TENANT_ID varchar(255)^
alter table SEC_SESSION_ATTR add SYS_TENANT_ID varchar(255)^
alter table SEC_USER_SUBSTITUTION add SYS_TENANT_ID varchar(255)^
alter table SEC_ENTITY_LOG add SYS_TENANT_ID varchar(255)^
alter table SEC_FILTER add SYS_TENANT_ID varchar(255)^
alter table SYS_FOLDER add SYS_TENANT_ID varchar(255)^
alter table SEC_PRESENTATION add SYS_TENANT_ID varchar(255)^
alter table SEC_SCREEN_HISTORY add SYS_TENANT_ID varchar(255)^
alter table SYS_SENDING_MESSAGE add SYS_TENANT_ID varchar(255)^
alter table SYS_SENDING_ATTACHMENT add SYS_TENANT_ID varchar(255)^
alter table SYS_ENTITY_SNAPSHOT add SYS_TENANT_ID varchar(255)^
alter table SEC_SESSION_LOG add SYS_TENANT_ID varchar(255)^

alter table SEC_USER drop constraint IDX_SEC_USER_UNIQ_LOGIN^
alter table SEC_USER add constraint IDX_SEC_USER_UNIQ_LOGIN unique (SYS_TENANT_ID, LOGIN_LC, DELETE_TS)^

alter table SEC_ROLE drop constraint IDX_SEC_ROLE_UNIQ_NAME^
alter table SEC_ROLE add constraint IDX_SEC_ROLE_UNIQ_NAME unique (SYS_TENANT_ID, NAME, DELETE_TS)^

alter table SEC_GROUP drop constraint IDX_SEC_GROUP_UNIQ_NAME^
alter table SEC_GROUP add constraint IDX_SEC_GROUP_UNIQ_NAME unique (SYS_TENANT_ID, NAME, DELETE_TS)^

alter table SEC_PERMISSION constraint IDX_SEC_PERMISSION_UNIQUE^
alter table SEC_PERMISSION constraint IDX_SEC_PERMISSION_UNIQUE unique (SYS_TENANT_ID, ROLE_ID, PERMISSION_TYPE, TARGET, DELETE_TS)

drop index IDX_SEC_LOC_CNSTRNT_MSG_UNIQUE on SEC_LOCALIZED_CONSTRAINT_MSG^
create unique index IDX_SEC_LOC_CNSTRNT_MSG_UNIQUE on SEC_LOCALIZED_CONSTRAINT_MSG (SYS_TENANT_ID, ENTITY_NAME, OPERATION_TYPE, DELETE_TS)^