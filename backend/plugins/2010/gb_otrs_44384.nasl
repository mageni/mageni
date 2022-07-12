###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_44384.nasl 12490 2018-11-22 13:45:33Z cfischer $
#
# OTRS 'AgentTicketZoom' HTML Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100884");
  script_version("$Revision: 12490 $");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2010-4071");
  script_bugtraq_id(44384);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2018-11-22 14:45:33 +0100 (Thu, 22 Nov 2018) $");
  script_tag(name:"creation_date", value:"2010-11-01 13:16:04 +0100 (Mon, 01 Nov 2010)");
  script_name("OTRS 'AgentTicketZoom' HTML Injection Vulnerability");

  script_tag(name:"impact", value:"Successful exploits will allow attacker-supplied HTML and script
  code to run in the context of the affected browser, potentially allowing the attacker to steal
  cookie-based authentication credentials or to control how the site is rendered to the user.
  Other attacks are also possible.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in application which fails to properly sanitize user-supplied
  input before using it in dynamically generated content.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to higher OTRS version or Apply patch from the vendor advisory link.");

  script_tag(name:"summary", value:"OTRS is prone to an HTML-injection vulnerability.

  This NVT has been replaced by NVT OID:1.3.6.1.4.1.25623.1.0.902352.");

  script_tag(name:"affected", value:"Versions prior to OTRS 2.4.9 are vulnerable.");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/44384");
  script_xref(name:"URL", value:"http://otrs.org/");
  script_xref(name:"URL", value:"http://otrs.org/advisory/OSA-2010-03-en/");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_otrs_xss_vuln.nasl