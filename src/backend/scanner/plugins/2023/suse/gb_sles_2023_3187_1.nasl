# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.3187.1");
  script_tag(name:"creation_date", value:"2023-08-07 04:28:45 +0000 (Mon, 07 Aug 2023)");
  script_version("2023-08-08T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-08-08 05:06:11 +0000 (Tue, 08 Aug 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:3187-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3187-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233187-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'javapackages-tools, javassist, mysql-connector-java, protobuf, python-python-gflags' package(s) announced via the SUSE-SU-2023:3187-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for javapackages-tools, javassist, mysql-connector-java, protobuf, python-python-gflags contains the following fixes:
Changes in mysql-connector-java:
- Restrict license to GPL-2.0-only
- Fix README adjustments
- Depend on log4j rather than log4j-mini and adjust log4j dependencies to
 account for the lack of log4j12 Provides in some code streams.
- Add missing Group tag
- Update to 8.0.25 (SOC-11543)
 Changes in 8.0.25
 * No functional changes: version alignment with MySQL Server 8.0.25.
 Changes in 8.0.24
 * Bug#102188 (32526663), AccessControlException with AuthenticationLdapSaslClientPlugin.
 * Bug#22508715, SETSESSIONMAXROWS() CALL ON CLOSED CONNECTION RESULTS IN NPE.
 * Bug#102131 (32338451), UPDATABLERESULTSET NPE WHEN USING DERIVED QUERIES OR VIEWS.
 * Bug#101596 (32151143), GET THE 'HOST' PROPERTY ERROR AFTER CALLING TRANSFORMPROPERTIES() METHOD.
 * Bug#20391832, SETOBJECT() FOR TYPES.TIME RESULTS IN EXCEPTION WHEN VALUE HAS FRACTIONAL PART.
 * Bug#97730 (31699993), xdev api: ConcurrentModificationException at Session.close.
 * Bug#99708 (31510398), mysql-connector-java 8.0.20 ASSERTION FAILED: Unknown message type: 57 s.close.
 * Bug#32122553, EXTRA BYTE IN COM_STMT_EXECUTE.
 * Bug#101558 (32141210), NULLPOINTEREXCEPTION WHEN EXECUTING INVALID QUERY WITH USEUSAGEADVISOR ENABLED.
 * Bug#102076 (32329915), CONTRIBUTION: MYSQL JDBC DRIVER RESULTSET.GETLONG() THROWS NUMBEROUTOFRANGE.
 * Bug#31747910, BUG 30474158 FIX IMPROVES JDBC COMPLIANCE BUT CHANGES DEFAULT RESULTSETTYPE HANDLING.
 * Bug#102321 (32405590), CALLING RESULTSETMETADATA.GETCOLUMNCLASSNAME RETURNS WRONG VALUE FOR DATETIME.
 * WL#14453, Pluggable authentication: new default behavior & user-less authentications.
 * WL#14392, Improve timeout error messages [classic].
 * WL#14202, XProtocol: Support connection close notification.
 Changes in 8.0.23
 * Bug#21789378, FORCED TO SET SERVER TIMEZONE IN CONNECT STRING.
 * Bug#95644 (30573281), JDBC GETDATE/GETTIME/GETTIMESTAMP INTERFACE BEHAVIOR CHANGE AFTER UPGRADE 8.0.
 * Bug#94457 (29402209), CONNECTOR/J RESULTSET.GETOBJECT( ..., OFFSETDATETIME.CLASS ) THROWS.
 * Bug#76775 (20959249), FRACTIONAL SECONDS IN TIME VALUES ARE NOT AVAILABLE VIA JDBC.
 * Bug#99013 (31074051), AN EXTRA HOUR GETS ADDED TO THE TIMESTAMP WHEN SUBTRACTING INTERVAL 'N' DAYS.
 * Bug#98695 (30962953), EXECUTION OF 'LOAD DATA LOCAL INFILE' COMMAND THROUGH JDBC FOR DATETIME COLUMN.
 * Bug#101413 (32099505), JAVA.TIME.LOCALDATETIME CANNOT BE CAST TO JAVA.SQL.TIMESTAMP.
 * Bug#101242 (32046007), CANNOT USE BYTEARRAYINPUTSTREAM AS ARGUMENTS IN PREPARED STATEMENTS AN MORE.
 * WL#14274, Support for authentication_ldap_sasl_client(SCRAM-SHA-256) authentication plugin.
 * WL#14206, Support for authentication_ldap_sasl_client(GSSAPI) authentication plugin.
 * WL#14207, Replace language in APIs and source code/docs.
 Changes in 8.0.22
 * Bug#98667 (31711961), 'All pipe instances are ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'javapackages-tools, javassist, mysql-connector-java, protobuf, python-python-gflags' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"javapackages-filesystem", rpm:"javapackages-filesystem~5.3.1~14.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
