###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_messaging_gateway_xss_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Symantec Messaging Gateway 'displayTab' Cross-Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:symantec:messaging_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804440");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-1648");
  script_bugtraq_id(66966);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-05-02 11:16:59 +0530 (Fri, 02 May 2014)");

  script_name("Symantec Messaging Gateway 'displayTab' Cross-Site Scripting Vulnerability");


  script_tag(name:"summary", value:"This host is running Symantec Messaging Gateway and is prone to cross-site
scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to input passed via the 'displayTab' GET parameter to
/brightmail/setting/compliance/DlpConnectFlow$view.flo is not properly sanitised before being returned to the
user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary HTML
and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Symantec Messaging Gateway 10.x before 10.5.2");

  script_tag(name:"solution", value:"Upgrade to Symantec Messaging Gateway 10.5.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58047");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126264/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Apr/256");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_messaging_gateway_detect.nasl");
  script_mandatory_keys("symantec_smg/detected");

  script_xref(name:"URL", value:"http://www.symantec.com/messaging-gateway");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!smgVer = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if (version_in_range(version:smgVer, test_version:"10.0", test_version2:"10.5.1")) {
  report = report_fixed_ver(  installed_version:smgVer, fixed_version:"10.5.2" );
  security_message(port:0, data:report);
  exit(0);
}

exit(0);
