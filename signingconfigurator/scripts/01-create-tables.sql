# The following commands must be run in the 'psql' command line tool:

CREATE DATABASE signing;

\connect signing

CREATE SCHEMA signing;

SET search_path TO signing;

CREATE TABLE "signing"."profilesignatureparameters" (
    "profileid" character varying(255) NOT NULL,
    "archivetimestampcanonicalizationmethod" character varying(255),
    "archivetimestampcontainerform" character varying(255),
    "archivetimestampdigestalgorithm" character varying(255),
    "asiccontainertype" character varying(255),
    "contenttimestampcanonicalizationmethod" character varying(255),
    "contenttimestampcontainerform" character varying(255),
    "contenttimestampdigestalgorithm" character varying(255),
    "created" timestamp NOT NULL,
    "digestalgorithm" character varying(255) NOT NULL,
    "generatetbswithoutcertificate" boolean,
    "isdefault" boolean,
    "maskgenerationfunction" character varying(255),
    "policydescription" character varying(255),
    "policydigestalgorithm" character varying(255),
    "policydigestvalue" bytea,
    "policyid" character varying(255),
    "policyqualifier" character varying(255),
    "policyspuri" character varying(255),
    "referencedigestalgorithm" character varying(255),
    "signwithexpiredcertificate" boolean,
    "signaturelevel" character varying(255) NOT NULL,
    "signaturepackaging" character varying(255) NOT NULL,
    "signaturetimestampcanonicalizationmethod" character varying(255),
    "signaturetimestampcontainerform" character varying(255),
    "signaturetimestampdigestalgorithm" character varying(255),
    "trustanchorbppolicy" boolean,
    "tspserver" character varying(255) NOT NULL,
    "updated" timestamp NOT NULL,
    "version" integer NOT NULL,
    CONSTRAINT "profilesignatureparameters_pkey" PRIMARY KEY ("profileid"),
    CONSTRAINT "uk_ki2dvs5cm22t4ae3pbicjvd1u" UNIQUE ("isdefault")
) WITH (oids = false);

CREATE TABLE "signing"."profilesignatureparameters_commitmenttypeindications" (
    "profilesignatureparameters_profileid" character varying(255) NOT NULL,
    "commitmenttypeindications" character varying(255),
    CONSTRAINT "fkfb4hrfeschj688ldpwievcq1t" FOREIGN KEY (profilesignatureparameters_profileid) REFERENCES profilesignatureparameters(profileid) NOT DEFERRABLE
) WITH (oids = false);

CREATE TABLE "signing"."profiletimestampparameters" (
    "profileid" character varying(255) NOT NULL,
    "canonicalizationmethod" character varying(255),
    "containerform" character varying(255),
    "created" timestamp NOT NULL,
    "digestalgorithm" character varying(255),
    "isdefault" boolean,
    "tspserver" character varying(255) NOT NULL,
    "updated" timestamp NOT NULL,
    "version" integer NOT NULL,
    CONSTRAINT "profiletimestampparameters_pkey" PRIMARY KEY ("profileid"),
    CONSTRAINT "uk_10of7xgtpl6mbfv2ia6kumwwb" UNIQUE ("isdefault")
) WITH (oids = false);
