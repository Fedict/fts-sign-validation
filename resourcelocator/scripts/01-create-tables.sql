CREATE TABLE "resources"."signingtype" (
    "name" character varying(255) NOT NULL,
    "uri" character varying(255),
    "active" boolean NOT NULL,
    "description" character varying(255),
    "logo" oid,
    "minimumversion" character varying(255),
    CONSTRAINT "signingtype_pkey" PRIMARY KEY ("name")
) WITH (oids = false);


CREATE TABLE "resources"."signingtype_certificatetypes" (
    "signingtype_name" character varying(255) NOT NULL,
    "certificatetypes" character varying(255),
    CONSTRAINT "fk6ae6bgtgabw7s086rmt9kc03t" FOREIGN KEY (signingtype_name) REFERENCES signingtype(name) NOT DEFERRABLE
) WITH (oids = false);