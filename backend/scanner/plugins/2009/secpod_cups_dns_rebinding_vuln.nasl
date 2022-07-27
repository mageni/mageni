###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cups_dns_rebinding_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# CUPS HTTP Host Header DNS Rebinding Attacks
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900349");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2009-0164");
  script_bugtraq_id(34665);
  script_name("CUPS HTTP Host Header DNS Rebinding Attacks");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_cups_detect.nasl");
  script_require_ports("Services/www", 631);
  script_mandatory_keys("CUPS/installed");

  script_xref(name:"URL", value:"http://www.cups.org/str.php?L3118");
  script_xref(name:"URL", value:"http://www.cups.org/articles.php?L582");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=263070");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490597");

  script_tag(name:"impact", value:"An attacker can use this weakness to carry out certain attacks such as
  DNS rebinding against the vulnerable server.");

  script_tag(name:"affected", value:"CUPS version prior to 1.3.10.");

  script_tag(name:"insight", value:"The flaw is cause due to insufficient validation of the HTTP Host header
  in a client request.");

  script_tag(name:"solution", value:"Upgrade to version 1.3.10 or later.");

  script_tag(name:"summary", value:"This host is running CUPS, and is prone to DNS Rebinding Attacks.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( vers !~ "[0-9]+\.[0-9]+\.[0-9]+") exit( 0 ); # Version is not exact enough

if( version_is_less( version:vers, test_version:"1.3.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.10" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );