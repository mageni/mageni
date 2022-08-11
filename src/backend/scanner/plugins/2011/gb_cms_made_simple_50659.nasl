###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cms_made_simple_50659.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# CMS Made Simple Remote Database Corruption Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103332");
  script_bugtraq_id(50659);
  script_version("$Revision: 12018 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("CMS Made Simple Remote Database Corruption Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-15 11:29:14 +0100 (Tue, 15 Nov 2011)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("cms_made_simple_detect.nasl");
  script_mandatory_keys("cmsmadesimple/installed");

  script_xref(name:"URL", value:"http://www.cmsmadesimple.org/2011/08/Announcing-CMSMS-1-9-4-3---Security-Release/");
  script_xref(name:"URL", value:"http://www.cmsmadesimple.org/");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more details.");

  script_tag(name:"summary", value:"CMS Made Simple is prone to a vulnerability that could result in the
  corruption of the database.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to corrupt the database.");

  script_tag(name:"affected", value:"Versions prior to CMS Made Simple 1.9.4.3 are vulnerable.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: vers, test_version: "1.9.4.3")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "1.9.4.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
