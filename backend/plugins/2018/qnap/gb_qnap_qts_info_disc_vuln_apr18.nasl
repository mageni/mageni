###############################################################################
# OpenVAS Vulnerability Test
#
# QNAP QTS 'sysinfoReq.cgi' Information Disclosure Vulnerability-Apr18
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813119");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2017-7630");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-04-20 10:36:37 +0530 (Fri, 20 Apr 2018)");
  script_name("QNAP QTS 'sysinfoReq.cgi' Information Disclosure Vulnerability-Apr18");

  script_tag(name:"summary", value:"This host is running QNAP QTS and is prone
  to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  'sysinfoReq.cgi' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"QNAP QTS 4.2.x prior to 4.2.6 build
  20170905 and 4.3.x prior to 4.3.3.0351 Build 20171023.");

  script_tag(name:"solution", value:"Upgrade to QNAP QTS 4.2.6 build
  20170905 or 4.3.3.0351 Build 20171023 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.qnap.com/nl-nl/search/?q=CVE-2017-7630");
  script_xref(name:"URL", value:"https://www.qnap.com/nl-nl/releasenotes/index.php");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts", "qnap/version", "qnap/build");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("version_func.inc");

if(!version = get_kb_item("qnap/version")) exit(0);
if(!build = get_kb_item("qnap/build")) exit(0);

cv = version + '.' + build;

if(version_is_less( version:cv, test_version: "4.2.6.20170905"))
{
  fix = "4.2.6";
  fix_build = "20170905";
}
else if(cv =~ "^(4\.3\.)" && version_is_less(version:cv, test_version: "4.3.3.0351.20171023"))
{
  fix = "4.3.3.0351";
  fix_build = "20171023";
}

if(fix)
{
  report = report_fixed_ver(installed_version:version, installed_build:build, fixed_version:fix, fixed_build:fix_build);
  security_message( port: 0, data: report );
  exit( 0 );
}
exit(0);
