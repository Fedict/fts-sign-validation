CREATE TABLE "signing"."profilesignatureparameters" (
    "profileid" character varying(255) NOT NULL,
    "asiccontainertype" character varying(255),
    "created" timestamp NOT NULL,
    "isdefault" boolean,
    "referencedigestalgorithm" character varying(255),
    "signaturealgorithm" character varying(255) NOT NULL,
    "signaturelevel" character varying(255) NOT NULL,
    "signaturepackaging" character varying(255) NOT NULL,
    "updated" timestamp NOT NULL,
    "version" integer NOT NULL,
    CONSTRAINT "profilesignatureparameters_pkey" PRIMARY KEY ("profileid"),
    CONSTRAINT "uk_ki2dvs5cm22t4ae3pbicjvd1u" UNIQUE ("isdefault")
) WITH (oids = false);