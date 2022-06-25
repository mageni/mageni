###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_webLogic_server_cpuapr2017-3236618_01.nasl 11923 2018-10-16 10:38:56Z mmartin $
#
# Oracle WebLogic Server Multiple Vulnerabilities-01 (cpuapr2017-3236618)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:bea:weblogic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810748");
  script_version("$Revision: 11923 $");
  script_cve_id("CVE-2017-5638", "CVE-2016-1181", "CVE-2017-3506");
  script_bugtraq_id(96729, 91068, 97884);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 12:38:56 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-19 14:58:02 +0530 (Wed, 19 Apr 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Oracle WebLogic Server Multiple Vulnerabilities-01 (cpuapr2017-3236618)");

  script_tag(name:"summary", value:"The host is running Oracle WebLogic Server
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist due to some unspecified
  error in the 'Samples (Struts 2)' and 'Web Services' sub-component within
  Oracle WebLogic Server.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary commands.");

  script_tag(name:"affected", value:"Oracle WebLogic Server versions 10.3.6.0,
  12.1.3.0, 12.2.1.0, 12.2.1.1 and 12.2.1.2");

  script_tag(name:"solution", value:"Apply update from the link mentioned below.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("oracle_webLogic_server_detect.nasl");
  script_mandatory_keys("OracleWebLogicServer/installed");
  script_require_ports("Services/www", 7001);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!webPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!webVer = get_app_version(cpe:CPE, port:webPort)){
  exit(0);
}

affected = make_list('10.3.6.0', '12.1.3.0', '12.2.1.0', '12.2.1.2', '12.2.1.1');
foreach version (affected)
{
  if( webVer == version)
  {
    report = report_fixed_ver(installed_version:webVer, fixed_version:"Apply the appropriate patch");
    security_message(data:report, port:webPort);
    exit(0);
  }
}
