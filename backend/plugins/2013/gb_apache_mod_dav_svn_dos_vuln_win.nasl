###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_mod_dav_svn_dos_vuln_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Apache HTTP Server 'mod_dav_svn' Denial of Service Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803743");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-1896");
  script_bugtraq_id(61129);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-08-21 18:57:17 +0530 (Wed, 21 Aug 2013)");
  script_name("Apache HTTP Server 'mod_dav_svn' Denial of Service Vulnerability (Windows)");


  script_tag(name:"summary", value:"The host is running Apache HTTP Server and is prone to denial of service
vulnerability.");
  script_tag(name:"vuldetect", value:"Get the installed version Apache HTTP Server with the help of detect NVT
and check it is vulnerable or not.");
  script_tag(name:"solution", value:"Upgrade to Apache HTTP Server 2.2.25 or later.");
  script_tag(name:"insight", value:"The flaw is due to an error in 'mod_dav.c', It does not properly determine
whether DAV is enabled for a URI.");
  script_tag(name:"affected", value:"Apache HTTP Server version before 2.2.25 on windows.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to cause a denial of
service (segmentation fault) via a MERGE request in which the URI is
configured for handling by the mod_dav_svn module.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.apache.org/dist/httpd/Announcement2.2.html");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc/httpd/httpd/trunk/modules/dav/main/mod_dav.c?view=log");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/installed", "Host/runs_windows");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!httpPort = get_app_port(cpe:CPE)) exit(0);
if(!httpVers = get_app_version(cpe:CPE, port:httpPort)) exit(0);

if(version_is_less(version:httpVers, test_version:"2.2.25"))
{
  security_message(port:httpPort);
  exit(0);
}
