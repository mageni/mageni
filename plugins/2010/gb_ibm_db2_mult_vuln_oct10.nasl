###############################################################################
# OpenVAS Vulnerability Test
#
# IBM DB2 Multiple Vulnerabilities (Oct10)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801522");
  script_version("2019-05-17T11:35:17+0000");
  script_tag(name:"last_modification", value:"2019-05-17 11:35:17 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2010-10-08 08:29:14 +0200 (Fri, 08 Oct 2010)");
  script_cve_id("CVE-2010-3734", "CVE-2010-3731", "CVE-2010-3732", "CVE-2010-3733",
                "CVE-2010-3736", "CVE-2010-3735", "CVE-2010-3737", "CVE-2010-3738",
                "CVE-2010-3740", "CVE-2010-3739");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("IBM DB2 Multiple Vulnerabilities (Oct10)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41686");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2544");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC62856");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ56428");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR34218");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl");
  script_mandatory_keys("IBM-DB2/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass security restrictions,
  gain knowledge of sensitive information or cause a denial of service.");

  script_tag(name:"affected", value:"IBM DB2 versions 9.5 before Fix Pack 6a");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error in 'Install' component, which enforces an unintended limit on
    password length, which makes it easier for attackers to obtain access via
    a brute-force attack.

  - A buffer overflow in the 'Administration Server' component, which allows an
    attacker to cause a denial of service via unspecified vectors.

  - An error in 'DRDA Services' component, which allows remote authenticated
    users to cause a denial of service.

  - The 'Engine Utilities' component uses world-writable permissions for the
   'sqllib/cfg/db2sprf' file, which allows local users to gain privileges by
    modifying this file.

  - A memory leak in the 'Relational Data Services' component, when the
    connection concentrator is enabled.

  - The 'Query Compiler, Rewrite, Optimizer' component, allows remote
    authenticated users to cause a denial of service (CPU consumption).

  - The 'Security' component logs 'AUDIT' events by using a USERID and an
    AUTHID value corresponding to the instance owner, instead of a USERID and
    an AUTHID value corresponding to the logged-in user account.

  - The 'Net Search Extender' (NSE) implementation in the Text Search component
    does not properly handle an alphanumeric Fuzzy search.

  - The audit facility in the 'Security' component uses instance-level audit
    settings to capture connection (aka CONNECT and AUTHENTICATION) events in
    certain circumstances in which database-level audit settings were intended.");

  script_tag(name:"solution", value:"Update DB2 version 9.5 Fix Pack 6a");

  script_tag(name:"summary", value:"The host is running IBM DB2 and is prone to multiple vulnerabilities.");

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

if (version =~ "^09\.05\.") {
  if (version_is_less(version: version, test_version: "09.05.6")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "09.05.6");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
