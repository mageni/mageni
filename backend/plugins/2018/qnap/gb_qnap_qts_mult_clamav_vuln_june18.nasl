##############################################################################
# OpenVAS Vulnerability Test
#
# QNAP QTS Multiple ClamAV Vulnerabilities-June18
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813520");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2017-12374", "CVE-2017-12375", "CVE-2017-12376", "CVE-2017-12377",
                "CVE-2017-12378", "CVE-2017-12379", "CVE-2017-12380");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-06-11 17:13:13 +0530 (Mon, 11 Jun 2018)");
  script_name("QNAP QTS Multiple ClamAV Vulnerabilities-June18");

  script_tag(name:"summary", value:"This host is running QNAP QTS and is prone
  to multiple ClamAV vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to -

  - A lack of input validation checking mechanisms during certain mail parsing
    operations and functions.

  - An improper input validation checking mechanisms when handling Portable
    Document Format (.pdf) files sent to an affected device.

  - An improper input validation checking mechanisms in mew packet files
    sent to an affected device.

  - An improper input validation checking mechanisms of '.tar' (Tape Archive)
    files sent to an affected device.

  - An improper input validation checking mechanisms in the message parsing
    function on an affected system.

  - An improper input validation checking mechanisms during certain mail
    parsing functions of the ClamAV software.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to launch denial of service (DoS) attacks or run arbitrary code on
  the NAS.");

  script_tag(name:"affected", value:"QNAP QTS versions 4.2.6 build 20171208 and
  earlier, 4.3.3 build 20180126 and earlier, 4.3.4 build 20180323 and earlier.");

  script_tag(name:"solution", value:"Upgrade to QNAP QTS 4.2.6 build 20180504,
  4.3.3 build  20180402 or 4.3.4 build 20180413 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://www.qnap.com/en-in/security-advisory/nas-201805-10");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts", "qnap/version", "qnap/build", "qnap/port");
  script_require_ports("Services/www", 80, 8080);
  exit(0);
}

include("version_func.inc");

if(!version = get_kb_item("qnap/version")) exit(0);
if(!build = get_kb_item("qnap/build")) exit(0);
if(!port = get_kb_item("qnap/port")) exit(0);

cv = version + '.' + build;

if( cv =~ "^4\.2\.6" && version_is_less(version:cv, test_version: "4.2.6.20180504"))
{
  fix = "4.2.6";
  fix_build = "20180504";
}

else if( cv =~ "^4\.3\.3" && version_is_less(version:cv, test_version: "4.3.3.20180402"))
{
  fix = "4.3.3";
  fix_build = "20180402";
}

else if( cv =~ "^4\.3\.4" && version_is_less(version:cv, test_version: "4.3.4.20180413"))
{
  fix = "4.3.4";
  fix_build = "20180413";
}

if(fix)
{
  report = report_fixed_ver(installed_version:version, installed_build:build, fixed_version:fix, fixed_build:fix_build);
  security_message( port: port, data: report );
  exit( 0 );
}

exit(99);
