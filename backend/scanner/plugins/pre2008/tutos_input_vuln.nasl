# OpenVAS Vulnerability Test
# $Id: tutos_input_vuln.nasl 13975 2019-03-04 09:32:08Z cfischer $
# Description: Tutos input validation Issues
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

CPE = 'cpe:/a:tutos:tutos';

#  Ref: Francois SORIN <francois.sorin@kereval.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14793");
  script_version("$Revision: 13975 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10129);
  script_cve_id("CVE-2003-0481", "CVE-2003-0482");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Tutos input validation Issues");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("sw_tutos_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tutos/installed");

  script_tag(name:"solution", value:"Upgrade to Tutos-1.1.20040412 or newer");
  script_tag(name:"summary", value:"The remote host is running Tutos, an open-source team organization software
 package written in PHP.

 The remote version of this software is vulnerable to multiple input validation
 flaws which may allow an authenticated user to perform a cross site scripting
 attack, path disclosure attack or a SQL injection against the remote service.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");


if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( egrep( pattern:"(0\..*|1\.(0\.|1\.(2003|20040[1-3]|2004040[0-9]|2004041[01])))", string:vers ) ) {

  security_message( port:port );
  exit( 0 );
}

exit( 99 );
