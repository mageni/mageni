###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_app_serv_xst_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Sun Java System Application Server Cross Site Tracing Vulnerability
#
# Authors:
# Veerendra G <veerendragg@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:sun:java_system_application_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800162");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-08 10:53:20 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0386");

  script_name("Sun Java System Application Server Cross Site Tracing Vulnerability");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/867593");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-200942-1");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_sun_java_app_serv_detect.nasl");
  script_mandatory_keys("sun_java_appserver/installed");
  script_require_ports("Services/www", 80, 8080);

  script_tag(name:"impact", value:"Successful exploitation lets the attackers to to get sensitive information,
such as cookies or authentication data, contained in the HTTP headers.");

  script_tag(name:"affected", value:"Sun Java System Application Server Standard Edition 7 and later updates,
Sun Java System Application Server Standard Edition 7 2004Q2 and later updates");

  script_tag(name:"insight", value:"An error exists while processing HTTP TRACE method and returns contents of
clients HTTP requests in the entity-body of the TRACE response. An attacker can use this behavior to access
sensitive information, such as cookies or authentication data, contained in the HTTP headers of the request.");

  script_tag(name:"summary", value:"This host has Sun Java System Application Server running which is prone to
Cross Site Tracing vulnerability.");

  script_tag(name:"solution", value:"See the vendor advisory for a workaround.");

  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^7") {
  if (version =~ "^(7.0|7 2004Q2)") {
    security_message(port);
    exit(0);
  }
}

exit(99);
