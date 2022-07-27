###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fishey_53603.nasl 11651 2018-09-27 11:53:00Z asteins $
#
# Atlassian JIRA FishEye and Crucible Plugins XML Parsing Unspecified Security Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103490");
  script_bugtraq_id(53603);
  script_version("$Revision: 11651 $");

  script_name("Atlassian JIRA FishEye and Crucible Plugins XML Parsing Unspecified Security Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53603");
  script_xref(name:"URL", value:"http://www.atlassian.com/software/jira/");
  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/FE-4016");
  script_xref(name:"URL", value:"http://confluence.atlassian.com/display/FISHEYE/FishEye+and+Crucible+Security+Advisory+2012-05-17");

  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-27 13:53:00 +0200 (Thu, 27 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-05-18 12:55:55 +0200 (Fri, 18 May 2012)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_FishEye_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("FishEye/installed");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"summary", value:"The FishEye and Crucible plugins for JIRA are prone to an
unspecified security vulnerability because they fail to properly
handle crafted XML data.

Exploiting this issue allows remote attackers to cause denial-of-
service conditions or to disclose local sensitive files in the context
of an affected application.

FishEye and Crucible versions up to and including 2.7.11 are
vulnerable.");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = 'cpe:/a:atlassian:fisheye';

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"2.7", test_version2:"2.7.11") ||
   version_in_range(version:vers, test_version:"2.6", test_version2:"2.6.7")  ||
   version_in_range(version:vers, test_version:"2.5", test_version2:"2.5.7")) {
  security_message(port:port);
  exit(0);
}

exit(99);
