###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_2168_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for phpMyAdmin openSUSE-SU-2016:2168-1 (phpMyAdmin)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851387");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-08-30 05:44:06 +0200 (Tue, 30 Aug 2016)");
  script_cve_id("CVE-2016-6606", "CVE-2016-6607", "CVE-2016-6608", "CVE-2016-6609",
                "CVE-2016-6610", "CVE-2016-6611", "CVE-2016-6612", "CVE-2016-6613",
                "CVE-2016-6614", "CVE-2016-6615", "CVE-2016-6616", "CVE-2016-6617",
                "CVE-2016-6618", "CVE-2016-6619", "CVE-2016-6620", "CVE-2016-6621",
                "CVE-2016-6622", "CVE-2016-6623", "CVE-2016-6624", "CVE-2016-6625",
                "CVE-2016-6626", "CVE-2016-6627", "CVE-2016-6628", "CVE-2016-6629",
                "CVE-2016-6630", "CVE-2016-6631", "CVE-2016-6632", "CVE-2016-6633");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for phpMyAdmin openSUSE-SU-2016:2168-1 (phpMyAdmin)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpMyAdmin'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"phpMyAdmin was updated to version 4.4.15.8 (2016-08-16) to fix the
  following issues:

  - Upstream changelog for 4.4.15.8:

  * Improve session cookie code for openid.php and signon.php example files

  * Full path disclosure in openid.php and signon.php example files

  * Unsafe generation of BlowfishSecret (when not supplied by the user)

  * Referrer leak when phpinfo is enabled

  * Use HTTPS for wiki links

  * Improve SSL certificate handling

  * Fix full path disclosure in debugging code

  * Administrators could trigger SQL injection attack against users

  - other fixes

  * Remove Swekey support

  * Weaknesses with cookie encryption see PMASA-2016-29 (CVE-2016-6606,
  CWE-661)

  * Multiple XSS vulnerabilities see PMASA-2016-30 (CVE-2016-6607, CWE-661)

  * Multiple XSS vulnerabilities see PMASA-2016-31 (CVE-2016-6608, CWE-661)

  * PHP code injection see PMASA-2016-32 (CVE-2016-6609, CWE-661)

  * Full path disclosure see PMASA-2016-33 (CVE-2016-6610, CWE-661)

  * SQL injection attack see PMASA-2016-34 (CVE-2016-6611, CWE-661)

  * Local file exposure through LOAD DATA LOCAL INFILE see PMASA-2016-35
  (CVE-2016-6612, CWE-661)

  * Local file exposure through symlinks with UploadDir see PMASA-2016-36
  (CVE-2016-6613, CWE-661)

  * Path traversal with SaveDir and UploadDir see PMASA-2016-37
  (CVE-2016-6614, CWE-661)

  * Multiple XSS vulnerabilities see PMASA-2016-38 (CVE-2016-6615, CWE-661)

  * SQL injection vulnerability as control user see PMASA-2016-39
  (CVE-2016-6616, CWE-661)

  * SQL injection vulnerability see PMASA-2016-40 (CVE-2016-6617, CWE-661)

  * Denial-of-service attack through transformation feature see
  PMASA-2016-41 (CVE-2016-6618, CWE-661)

  * SQL injection vulnerability as control user see PMASA-2016-42
  (CVE-2016-6619, CWE-661)

  * Verify data before unserializing see PMASA-2016-43 (CVE-2016-6620,
  CWE-661)

  * SSRF in setup script see PMASA-2016-44 (CVE-2016-6621, CWE-661)

  * Denial-of-service attack with $cfg['AllowArbitraryServer'] = true and
  persistent connections see PMASA-2016-45 (CVE-2016-6622, CWE-661)

  * Denial-of-service attack by using for loops see PMASA-2016-46
  (CVE-2016-6623, CWE-661)

  * Possible circumvention of IP-based allow/deny rules with IPv6 and
  proxy server see PMASA-2016-47 (CVE-2016-6624, CWE-661)

  * Detect if user is logged in see PMASA-2016-48 (CVE-2016-6625, CWE-661)

  * Bypass URL redirection protection see PMASA-2016-49 (CVE-2016-6626,
  CWE-661)

  * Referrer leak see PMASA-2016-50 (CVE-201 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"phpMyAdmin on openSUSE Leap 42.1, openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"phpMyAdmin", rpm:"phpMyAdmin~4.4.15.8~39.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
