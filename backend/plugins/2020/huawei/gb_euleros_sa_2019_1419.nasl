# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1419");
  script_version("2020-01-23T11:43:35+0000");
  script_cve_id("CVE-2013-4352", "CVE-2013-5704", "CVE-2013-6438", "CVE-2014-0098", "CVE-2014-0117", "CVE-2014-0118", "CVE-2014-0226", "CVE-2014-0231", "CVE-2014-3581", "CVE-2015-3183", "CVE-2015-3185", "CVE-2016-0736", "CVE-2016-2161", "CVE-2016-5387", "CVE-2016-8743", "CVE-2017-15710", "CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7668", "CVE-2017-7679", "CVE-2017-9788", "CVE-2017-9798", "CVE-2018-1303", "CVE-2018-1312", "CVE-2019-0217");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 11:43:35 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:43:35 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for httpd (EulerOS-SA-2019-1419)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1419");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'httpd' package(s) announced via the EulerOS-SA-2019-1419 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The log_cookie function in mod_log_config.c in the mod_log_config module in the Apache HTTP Server before 2.4.8 allows remote attackers to cause a denial of service (segmentation fault and daemon crash) via a crafted cookie that is not properly handled during truncation.(CVE-2014-0098)

A race condition flaw, leading to heap-based buffer overflows, was found in the mod_status httpd module. A remote attacker able to access a status page served by mod_status on a server using a threaded Multi-Processing Module (MPM) could send a specially crafted request that would cause the httpd child process to crash or, possibly, allow the attacker to execute arbitrary code with the privileges of the 'apache' user.(CVE-2014-0226)

It was discovered that the HTTP parser in httpd incorrectly allowed certain characters not permitted by the HTTP protocol specification to appear unencoded in HTTP request headers. If httpd was used in conjunction with a proxy or backend server that interpreted those characters differently, a remote attacker could possibly use this flaw to inject data into HTTP responses, resulting in proxy cache poisoning.(CVE-2016-8743)

A NULL pointer dereference flaw was found in the way the mod_cache httpd module handled Content-Type headers. A malicious HTTP server could cause the httpd child process to crash when the Apache HTTP server was configured to proxy to a server with caching enabled.(CVE-2014-3581)

Multiple flaws were found in the way httpd parsed HTTP requests and responses using chunked transfer encoding. A remote attacker could use these flaws to create a specially crafted request, which httpd would decode differently from an HTTP proxy software in front of it, possibly leading to HTTP request smuggling attacks.(CVE-2015-3183)

In Apache httpd 2.0.23 to 2.0.65, 2.2.0 to 2.2.34, and 2.4.0 to 2.4.29, mod_authnz_ldap, if configured with AuthLDAPCharsetConfig, uses the Accept-Language header value to lookup the right charset encoding when verifying the user's credentials. If the header value is not present in the charset conversion table, a fallback mechanism is used to truncate it to a two characters value to allow a quick retry (for example, 'en-US' is truncated to 'en'). A header value of less than two characters forces an out of bound write of one NUL byte to a memory location that is not part of the string. In the worst case, quite unlikely, the process would crash which could be used as a Denial of Service attack. In the more likely case, this memory is already reserved for future use and the issue has no effect at all.(CVE-2017-15710)

A NULL pointer derefere ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'httpd' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.4.6~80.1.h6", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.4.6~80.1.h6", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.4.6~80.1.h6", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);