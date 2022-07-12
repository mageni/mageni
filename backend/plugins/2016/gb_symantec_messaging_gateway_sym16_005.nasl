###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_messaging_gateway_sym16_005.nasl 12083 2018-10-25 09:48:10Z cfischer $
#
# Symantec Messaging Gateway Multiple Security Issues (SYM16-005)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

CPE = "cpe:/a:symantec:messaging_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105620");
  script_version("$Revision: 12083 $");
  script_cve_id("CVE-2016-2203", "CVE-2016-2204");
  script_bugtraq_id(86137, 86138);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 11:48:10 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-22 10:36:01 +0200 (Fri, 22 Apr 2016)");

  script_name("Symantec Messaging Gateway Multiple Security Issues (SYM16-005)");

  script_tag(name:"summary", value:"SMG is vulnerable to two privilege escalation issues impacting Symantecs
Messaging Gateway Appliance 10.x management console.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Symantec Messaging Gateway (SMG) Appliance management console was susceptible
to potential recovery of the AD password by any user with at least authorized read access to the appliance. Also,
an admin or support user could potentially escalate a lower-privileged access to root on the appliance by escaping
their terminal window to a privileged shell.");

  script_tag(name:"impact", value:"Successful exploitation could result in elevated access to the SMG Appliance
management console or to the network environment.");

  script_tag(name:"affected", value:"SMG 10.6.0-7 and earlier.");
  script_tag(name:"solution", value:"Update to SMG 10.6.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year&suid=20160418_00");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_messaging_gateway_detect.nasl");
  script_mandatory_keys("symantec_smg/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version(cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version =~ "^10\." )
{
  if( version_is_less( version:version, test_version:"10.6.1" ) )
  {
    report = report_fixed_ver( installed_version:version, fixed_version:'10.6.1' );
    security_message( port:0, data:report );
    exit(0);
  }
}

exit( 99 );
