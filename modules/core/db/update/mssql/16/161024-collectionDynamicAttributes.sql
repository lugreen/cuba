alter table SYS_CATEGORY_ATTR add column IS_COLLECTION tinyint;
alter table SYS_ATTR_VALUE add column PARENT_ID uniqueidentifier;
alter table SYS_ATTR_VALUE add constraint SYS_ATTR_VALUE_ATTR_VALUE_PARENT_ID foreign key (PARENT_ID) references SYS_ATTR_VALUE(ID);