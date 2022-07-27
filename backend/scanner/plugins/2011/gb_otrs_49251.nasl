###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_49251.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# OTRS 'AdminPackageManager.pm' Local File Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
CPE = "cpe:/a:otrs:otrs";


if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103216");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-2746");
  script_bugtraq_id(49251);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-22 16:04:33 +0200 (Mon, 22 Aug 2011)");
  script_name("OTRS 'AdminPackageManager.pm' Local File Disclosure Vulnerability");


  script_tag(name:"impact", value:"Exploiting this vulnerability would allow an attacker to obtain potentially
sensitive information from local files on computers running the vulnerable
application. This may aid in further attacks.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An error exists in application which fails to adequately validate
user-supplied input.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"OTRS is prone to a local file-disclosure vulnerability");
  script_tag(name:"affected", value:"Open Ticket Request System (OTRS) version 2.4.x before 2.4.11 and 3.x before 3.0.8");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49251");
  script_xref(name:"URL", value:"http://otrs.org/");
  script_xref(name:"URL", value:"http://otrs.org/advisory/OSA-2011-03-en/");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_otrs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OTRS/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(vers = get_app_version(cpe:CPE, port:port))
{
  if(version_in_range(version: vers, test_version:"2.4", test_version2:"2.4.10") ||
     version_in_range(version: vers, test_version:"3.0", test_version2:"3.0.7"))
  {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
