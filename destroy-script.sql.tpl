DO $do$
DECLARE
  each_schema text;
  affected_schemas text := '${affected_schemas}';
  granted_privileges text := '${granted_privileges}';
BEGIN
  IF ${make_admin_own} THEN
    GRANT "${db_owner}" TO "${admin_user}";
    RAISE NOTICE 'DB owner role granted to admin user.';
  END IF;

  IF affected_schemas = 'ALL' THEN
    FOR each_schema IN SELECT nspname FROM pg_namespace where nspname != 'pg_toast' 
      and nspname != 'pg_statistic' 
      and nspname != 'pg_catalog' 
      and nspname != 'information_schema'
    LOOP
      EXECUTE FORMAT('REVOKE %s ON SCHEMA "%s" FROM "${group_role}"', granted_privileges, each_schema);
      RAISE NOTICE '% privileges were granted on schema %.', granted_privileges, each_schema;
    END LOOP;
  ELSE
    EXECUTE FORMAT('REVOKE %s ON SCHEMA %s FROM "${group_role}"', granted_privileges, affected_schemas);
    RAISE NOTICE '% privileges were granted on schema(s) %.', granted_privileges, affected_schemas;
  END IF;

  IF ${make_admin_own} THEN
    REVOKE "${db_owner}" FROM "${admin_user}";
    RAISE NOTICE 'DB owner role revoked from admin user.';
  END IF;
END
$do$;
