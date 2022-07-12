###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kallithea_csrf_vuln.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# Kallithea < 0.2 CSRF Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:kallithea:kallithea";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112059");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2015-0276");
  script_bugtraq_id(74052);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-27 15:07:24 +0200 (Wed, 27 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Kallithea < 0.2 CSRF Vulnerability");

  script_tag(name:"summary", value:"A vulnerability has been found in Kallithea,
      allowing attackers to gain unauthorised access to the account of a logged in user.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Pages that present forms to the user and accept user input don't provide synchronisation tokens to prevent cross-site request forgery.

    It is possible to change an email address of a user by tricking them into clicking a link that initiates a malicious HTTP request.

    After this, the attacker can request a password reset, the link is then sent to their new email address.
    Then the attacker changes the email address back to the original, and doesn't log out, saving the cookie.

    At this point, the attacker has full access to the user's account. The user can't login (the password has changed),
    but might think that he forgot the password, has an account lockout, or an expired account. The user does a password reset, but the attacker still has the access.");

  script_tag(name:"impact", value:"The vulnerability allows attackers to steal the account of an active user by using social engineering techniques.
    In the case the user also has administrator rights, it is possible for the attacker to gain full administrator access to the Kallithea instance.");

  script_tag(name:"affected", value:"Kallithea before version 0.2");

  script_tag(name:"solution", value:"Upgrade to Kallithea version 0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/04/10/8");
  script_xref(name:"URL", value:"https://kallithea-scm.org/security/cve-2015-0276.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kallithea_detect.nasl");
  script_mandatory_keys("Kallithea/Installed");
  script_require_ports("Services/www", 5000);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ver = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if(version_is_less(version:ver, test_version:"0.2"))
{
  report = report_fixed_ver(installed_version:ver, fixed_version:"0.2");
  security_message(port:port, data:report);
  exit(0);
}
exit(99);
