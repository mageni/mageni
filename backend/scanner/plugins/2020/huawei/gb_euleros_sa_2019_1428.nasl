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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1428");
  script_version("2020-01-23T11:45:03+0000");
  script_cve_id("CVE-2012-4464", "CVE-2012-4466", "CVE-2012-4522", "CVE-2012-5371", "CVE-2013-2065", "CVE-2013-4073", "CVE-2013-4164", "CVE-2013-4287", "CVE-2013-4363", "CVE-2014-4975", "CVE-2014-8080", "CVE-2014-8090", "CVE-2018-16395", "CVE-2018-16396", "CVE-2018-8780");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 11:45:03 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:45:03 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for ruby (EulerOS-SA-2019-1428)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1428");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'ruby' package(s) announced via the EulerOS-SA-2019-1428 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ruby 1.8.7 before patchlevel 371, 1.9.3 before patchlevel 286, and 2.0 before revision r37068 allows context-dependent attackers to bypass safe-level restrictions and modify untainted strings via the name_err_mesg_to_str API function, which marks the string as tainted, a different vulnerability than CVE-2011-1005.(CVE-2012-4466)

The REXML parser in Ruby 1.9.x before 1.9.3 patchlevel 551, 2.0.x before 2.0.0 patchlevel 598, and 2.1.x before 2.1.5 allows remote attackers to cause a denial of service (CPU and memory consumption) a crafted XML document containing an empty string in an entity that is used in a large number of nested entity references, aka an XML Entity Expansion (XEE) attack. NOTE: this vulnerability exists because of an incomplete fix for CVE-2013-1821 and CVE-2014-8080.(CVE-2014-8090)

Algorithmic complexity vulnerability in Gem::Version::VERSION_PATTERN in lib/rubygems/version.rb in RubyGems before 1.8.23.1, 1.8.24 through 1.8.25, 2.0.x before 2.0.8, and 2.1.x before 2.1.0, as used in Ruby 1.9.0 through 2.0.0p247, allows remote attackers to cause a denial of service (CPU consumption) via a crafted gem version that triggers a large amount of backtracking in a regular expression.(CVE-2013-4287)

The REXML parser in Ruby 1.9.x before 1.9.3-p550, 2.0.x before 2.0.0-p594, and 2.1.x before 2.1.4 allows remote attackers to cause a denial of service (memory consumption) via a crafted XML document, aka an XML Entity Expansion (XEE) attack.(CVE-2014-8080)

The OpenSSL::SSL.verify_certificate_identity function in lib/openssl/ssl.rb in Ruby 1.8 before 1.8.7-p374, 1.9 before 1.9.3-p448, and 2.0 before 2.0.0-p247 does not properly handle a '\\0' character in a domain name in the Subject Alternative Name field of an X.509 certificate, which allows man-in-the-middle attackers to spoof arbitrary SSL servers via a crafted certificate issued by a legitimate Certification Authority, a related issue to CVE-2009-2408.(CVE-2013-4073)

The rb_get_path_check function in file.c in Ruby 1.9.3 before patchlevel 286 and Ruby 2.0.0 before r37163 allows context-dependent attackers to create files in unexpected locations or with unexpected names via a NUL byte in a file path.(CVE-2012-4522)

(1) DL and (2) Fiddle in Ruby 1.9 before 1.9.3 patchlevel 426, and 2.0 before 2.0.0 patchlevel 195, do not perform taint checking for native functions, which allows context-dependent attackers to bypass intended $SAFE level restrictions.(CVE-2013-2065)

Algorithmic complexity vulnerability in Gem::Version::ANCHORED_VERSION_PATTERN in lib/rubygems/version.rb in RubyGems before 1.8.23.2, 1.8.24 through 1.8.26 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'ruby' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~2.0.0.648~33.h12", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~2.0.0.648~33.h12", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~2.0.0.648~33.h12", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-bigdecimal", rpm:"rubygem-bigdecimal~1.2.0~33.h12", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-io-console", rpm:"rubygem-io-console~0.4.2~33.h12", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-json", rpm:"rubygem-json~1.7.7~33.h12", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-psych", rpm:"rubygem-psych~2.0.0~33.h12", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rdoc", rpm:"rubygem-rdoc~4.0.0~33.h12", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygems", rpm:"rubygems~2.0.14.1~33.h12", rls:"EULEROSVIRT-3.0.1.0"))) {
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