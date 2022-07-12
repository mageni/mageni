###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_elog_xss_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# ELOG Logbook Cross Site Scripting Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

CPE = "cpe:/a:stefan_ritt:elog_web_logbook";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900939");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-09-15 09:32:43 +0200 (Tue, 15 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-7206");
  script_bugtraq_id(27526);
  script_name("ELOG Logbook Cross Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_elog_detect.nasl");
  script_mandatory_keys("ELOG/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/40124");
  script_xref(name:"URL", value:"https://midas.psi.ch/elog/download/ChangeLog");
  script_xref(name:"URL", value:"https://midas.psi.ch/elog/download/");

  script_tag(name:"impact", value:"Attackers can exploit this issue to steal cookie-based authentication
  credentials by conducting Cross-Site Scripting attacks on the affected system.");

  script_tag(name:"affected", value:"ELOG versions prior to 2.7.2.");

  script_tag(name:"insight", value:"An error occurs while processing malicious user supplied data passed into
  the 'logbook' module and can be exploited to inject arbitrary HTML and
  script code in the context of the affected application.");

  script_tag(name:"solution", value:"Upgrade ELOG Version to 2.7.2 or later. Please see the
  references for more info.");

  script_tag(name:"summary", value:"This host has ELOG installed and is prone to cross-site
  scripting vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

# nb: 2.7.2 => 2.7.2-2012
if( version_is_less( version:vers, test_version:"2.7.2.2012" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.7.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );