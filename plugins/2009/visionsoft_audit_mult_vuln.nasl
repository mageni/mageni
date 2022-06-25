###############################################################################
# OpenVAS Vulnerability Test
#
# Visionsoft Audit Multiple Vulnerabilities
#
# Authors:
# Tim Brown <timb@openvas.org>
#
# Copyright:
# Copyright (C) 2009 Tim Brown and Portcullis Computer Security Ltd
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:visionsoft:audit";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100951");
  script_version("2020-08-27T12:19:44+0000");
  script_tag(name:"last_modification", value:"2020-08-28 09:48:35 +0000 (Fri, 28 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-07-10 19:42:14 +0200 (Fri, 10 Jul 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-4148", "CVE-2007-4149", "CVE-2007-4150", "CVE-2007-4151", "CVE-2007-4152");
  script_name("Visionsoft Audit Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2009 Tim Brown");
  script_dependencies("gb_visionsoft_audit_detect.nasl");
  script_mandatory_keys("visionsoft/audit/detected");

  script_xref(name:"URL", value:"http://www.portcullis-security.com/197.php");
  script_xref(name:"URL", value:"http://www.portcullis-security.com/198.php");
  script_xref(name:"URL", value:"http://www.portcullis-security.com/199.php");
  script_xref(name:"URL", value:"http://www.portcullis-security.com/203.php");
  script_xref(name:"URL", value:"http://www.portcullis-security.com/204.php");
  script_xref(name:"URL", value:"http://www.portcullis-security.com/205.php");
  script_xref(name:"URL", value:"http://www.portcullis-security.com/206.php");
  script_xref(name:"URL", value:"http://www.portcullis-security.com/207.php");

  script_tag(name:"solution", value:"We recommend that Visionsoft are contacted for a patch.

  To mitigate this flaw filter inbound traffic to 5957/tcp to only known management hosts.");

  script_tag(name:"summary", value:"Visionsoft Audit is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The Visionsoft Audit on Demand service may be vulnerable to multiple issues
  which can be exploited remotely without authentication:

  - Heap overflow via LOG command (CVE-2007-4148)

  - Multiple arbitrary file overwrites via LOG and SETTINGSFILE command (CVE-2007-4149)

  - Denial of service via UNINSTALL command (CVE-2007-4149)

  Additionally, the underlying protocol for authentication has been reported as being vulnerable
  to replay attacks (CVE-2007-4152) and the settings file is typically installed with
  inappropriate permissions (CVE-2007-4150).");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];

if( version_is_less_equal( version:vers, test_version:"12.4.0.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"Contact the vendor", install_path:infos["location"] );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
