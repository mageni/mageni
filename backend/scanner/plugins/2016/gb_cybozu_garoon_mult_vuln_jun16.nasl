###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cybozu_garoon_mult_vuln_jun16.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Cybozu Garoon Multiple Vulnerabilities-01 Jun16
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################
CPE = "cpe:/a:cybozu:garoon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807849");
  script_version("$Revision: 12338 $");
  script_cve_id("CVE-2016-1190", "CVE-2016-1193", "CVE-2016-1192", "CVE-2016-1188",
                "CVE-2016-1189", "CVE-2016-1195", "CVE-2016-1196", "CVE-2016-1191",
                "CVE-2016-1197", "CVE-2016-1194");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-29 17:46:28 +0530 (Wed, 29 Jun 2016)");
  script_name("Cybozu Garoon Multiple Vulnerabilities-01 Jun16");

  script_tag(name:"summary", value:"This host is installed with cybozu garoon
  and is vulnerable to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple unspecified
  errors.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to bypass intended restrictions and obtain sensitive information.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"affected", value:"Cybozu Garoon versions 3.x and 4.x before
  4.2.1");

  script_tag(name:"solution", value:"Upgrade to Cybozu Garoon 4.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN25765762/index.html");
  script_xref(name:"URL", value:"https://support.cybozu.com/ja-jp/article/8877");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2016/JVNDB-2016-000095.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2016/JVNDB-2016-000077.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2016/JVNDB-2016-000093.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2016/JVNDB-2016-000081.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_cybozu_products_detect.nasl");
  script_mandatory_keys("CybozuGaroon/Installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://garoon.cybozu.co.jp");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!cyPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!cyVer = get_app_version(cpe:CPE, port:cyPort)){
  exit(0);
}

if(version_in_range(version:cyVer, test_version:"3.0", test_version2:"4.2.0"))
{
  report = report_fixed_ver(installed_version:cyVer, fixed_version:"4.2.1");
  security_message(data:report, port:cyPort);
  exit(0);
}
