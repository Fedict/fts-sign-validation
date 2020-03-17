CREATE TABLE "signing"."profilesignatureparameters" (
    "profileid" character varying(255) NOT NULL,
    "asiccontainertype" character varying(255),
    "created" timestamp NOT NULL,
    "referencedigestalgorithm" character varying(255),
    "signaturelevel" character varying(255) NOT NULL,
    "signaturepackaging" character varying(255) NOT NULL,
    "updated" timestamp NOT NULL,
    "version" integer NOT NULL,
    CONSTRAINT "profilesignatureparameters_pkey" PRIMARY KEY ("profileid")
) WITH (oids = false);


CREATE TABLE "signing"."profilesignatureparameters_supportedsignaturealgorithms" (
    "profilesignatureparameters_profileid" character varying(255) NOT NULL,
    "supportedsignaturealgorithms" character varying(255),
    CONSTRAINT "fk69ncsh7wxvmt59n7ttf1vjb4h" FOREIGN KEY (profilesignatureparameters_profileid) REFERENCES profilesignatureparameters(profileid) NOT DEFERRABLE
) WITH (oids = false);