###############################################################################
# OpenVAS Vulnerability Test
#
# Mahara 'groupviews.tpl' Cross Site Scripting Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100897");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2010-11-09 13:58:26 +0100 (Tue, 09 Nov 2010)");
  script_bugtraq_id(44705);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-3871");

  script_name("Mahara 'groupviews.tpl' Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/44705");
  script_xref(name:"URL", value:"http://wiki.mahara.org/Release_Notes/1.3.3");
  script_xref(name:"URL", value:"http://mahara.org/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_mahara_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mahara/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  details.");

  script_tag(name:"summary", value:"Mahara is prone to a cross-site scripting vulnerability because it
  fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary HTML and
  script code in the browser of an unsuspecting user in the context of
  the affected site. This may let the attacker steal cookie-based
  authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Versions prior to Mahara 1.3.3 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(vers = get_version_from_kb(port:port, app:"Mahara")) {
  if(version_is_less(version: vers, test_version: "1.3.3")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);