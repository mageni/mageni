# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4129.1");
  script_cve_id("CVE-2023-41080", "CVE-2023-44487");
  script_tag(name:"creation_date", value:"2023-10-20 04:21:45 +0000 (Fri, 20 Oct 2023)");
  script_version("2023-10-20T05:06:03+0000");
  script_tag(name:"last_modification", value:"2023-10-20 05:06:03 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-14 01:15:00 +0000 (Sat, 14 Oct 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4129-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4129-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234129-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat' package(s) announced via the SUSE-SU-2023:4129-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat fixes the following issues:
Tomcat was updated to version 9.0.82 (jsc#PED-6376, jsc#PED-6377):


Security issues fixed:


CVE-2023-41080: Avoid protocol relative redirects in FORM authentication. (bsc#1214666)


CVE-2023-44487: Fix HTTP/2 Rapid Reset Attack. (bsc#1216182)


Update to Tomcat 9.0.82:


Catalina

Add: 65770: Provide a lifecycle listener that will
 automatically reload TLS configurations a set time before the
 certificate is due to expire. This is intended to be used with
 third-party tools that regularly renew TLS certificates.
Fix: Fix handling of an error reading a context descriptor on
 deployment.
Fix: Fix rewrite rule qsd (query string discard) being ignored
 if qsa was also use, while it should instead take precedence.
Fix: 67472: Send fewer CORS-related headers when CORS is not
 actually being engaged.
Add: Improve handling of failures within recycle() methods.



Coyote

Fix: 67670: Fix regression with HTTP compression after code
 refactoring.
Fix: 67198: Ensure that the AJP connector attribute
 tomcatAuthorization takes precedence over the
 tomcatAuthentication attribute when processing an auth_type
 attribute received from a proxy server.
Fix: 67235: Fix a NullPointerException when an AsyncListener
 handles an error with a dispatch rather than a complete.
Fix: When an error occurs during asynchronous processing,
 ensure that the error handling process is only triggered once
 per asynchronous cycle.
Fix: Fix logic issue trying to match no argument method in
 IntropectionUtil.
Fix: Improve thread safety around readNotify and writeNotify
 in the NIO2 endpoint.
Fix: Avoid rare thread safety issue accessing message digest
 map.
Fix: Improve statistics collection for upgraded connections
 under load.
Fix: Align validation of HTTP trailer fields with standard
 fields.
Fix: Improvements to HTTP/2 overhead protection (bsc#1216182,
 CVE-2023-44487)



jdbc-pool

Fix: 67664: Correct a regression in the clean-up of
 unnecessary use of fully qualified class names in 9.0.81
 that broke the jdbc-pool.



Jasper

Fix: 67080: Improve performance of EL expressions in JSPs that
 use implicit objects



Update to Tomcat 9.0.80 (jsc#PED-6376, jsc#PED-6377):


Catalina:

Add RateLimitFilter which can be used to mitigate DoS and Brute Force attacks Move the management of the utility executor from the init()/destroy() methods of components to the start()/stop()
 methods.
Add org.apache.catalina.core.StandardVirtualThreadExecutor, a virtual thread based executor that may be used with
 one or more Connectors to process requests received by those Connectors using virtual threads. This Executor
 requires a minimum Java version of Java 21.
Add a per session Semaphore to the PersistentValve that ensures that, within a single Tomcat instance, there is no
 more than one concurrent request per session. Also expand the debug logging to include whether a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'tomcat' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Manager Server 4.2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~9.0.82~150200.46.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~9.0.82~150200.46.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-3_0-api", rpm:"tomcat-el-3_0-api~9.0.82~150200.46.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2_3-api", rpm:"tomcat-jsp-2_3-api~9.0.82~150200.46.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~9.0.82~150200.46.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-4_0-api", rpm:"tomcat-servlet-4_0-api~9.0.82~150200.46.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~9.0.82~150200.46.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~9.0.82~150200.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~9.0.82~150200.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-3_0-api", rpm:"tomcat-el-3_0-api~9.0.82~150200.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2_3-api", rpm:"tomcat-jsp-2_3-api~9.0.82~150200.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~9.0.82~150200.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-4_0-api", rpm:"tomcat-servlet-4_0-api~9.0.82~150200.46.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~9.0.82~150200.46.1", rls:"SLES15.0SP3"))) {
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
