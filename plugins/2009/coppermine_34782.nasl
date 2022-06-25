###############################################################################
# OpenVAS Vulnerability Test
# $Id: coppermine_34782.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Coppermine Photo Gallery 'css' Parameter Cross-Site Scripting
# Vulnerability
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:coppermine:coppermine_photo_gallery";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100175");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-1616");
  script_bugtraq_id(34782);

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Coppermine Photo Gallery 'css' Parameter Cross-Site Scripting Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("coppermine_detect.nasl");
  script_mandatory_keys("coppermine_gallery/installed");

  script_tag(name:"summary", value:"Coppermine Photo Gallery is prone to a cross-site scripting vulnerability
  because the application fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code in the
  browser of an unsuspecting user in the context of the affected site. This may allow the attacker to steal
  cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Versions prior to Coppermine Photo Gallery 1.4.22 are vulnerable.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34782");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port))
  exit(0);

if (version_is_less(version: version, test_version: "1.4.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.22");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);