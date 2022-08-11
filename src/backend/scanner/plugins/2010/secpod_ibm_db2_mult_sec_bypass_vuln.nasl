###############################################################################
# OpenVAS Vulnerability Test
#
# IBM DB2 Multiple Security Bypass Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901156");
  script_version("2019-05-17T11:35:17+0000");
  script_tag(name:"last_modification", value:"2019-05-17 11:35:17 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)");
  script_bugtraq_id(43291);
  script_cve_id("CVE-2010-3474", "CVE-2010-3475");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("IBM DB2 Multiple Security Bypass Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41444");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2425");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC68015");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC70406");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl");
  script_mandatory_keys("IBM-DB2/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass security restrictions.");

  script_tag(name:"affected", value:"IBM DB2 versions prior to 9.7 Fix Pack 3");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error in the application while revoking privileges on a database object
    from the 'PUBLIC' group, which does not mark the dependent functions as
    'INVALID'.

  - An error in the application while compiling a compound SQL statement with
    an 'update' statement can be exploited by an unprivileged user to execute
    the query from the dynamic SQL cache.");

  script_tag(name:"solution", value:"Upgrade to IBM DB2 version 9.7 Fix Pack 3 or later");

  script_tag(name:"summary", value:"The host is running IBM DB2 and is prone to multiple security
  bypass vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_proto(cpe: CPE, port: port, exit_no_version: TRUE)) exit(0);
version = infos["version"];
proto = infos["proto"];

if (version =~ "^09\.07\.") {
  if (version_is_less(version: version, test_version: "09.07.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "09.07.3");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
