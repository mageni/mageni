###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_inspircd_m_sasl_module_spoofing_vuln.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# InspIRCd 'm_sasl' Module SASL_EXTERNAL Authentication Spoofing Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810282");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2016-7142");
  script_bugtraq_id(92737);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-16 14:56:16 +0530 (Mon, 16 Jan 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("InspIRCd 'm_sasl' Module SASL_EXTERNAL Authentication Spoofing Vulnerability");

  script_tag(name:"summary", value:"The host is installed with InspIRCd Daemon
  and is prone to authentication spoofing vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in the
  'm_sasl' module in InspIRC, when used with a service that supports
  SASL_EXTERNAL authentication");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to spoof certificate fingerprints via crafted SASL messages to the
  IRCd. This allows any user to login as any other user that they know the
  certificate fingerprint of, and that user has services configured to accept
  SASL EXTERNAL login requests for.");

  script_tag(name:"affected", value:"InspIRCd versions before 2.0.23.");

  script_tag(name:"solution", value:"Upgrade to InspIRCd version 2.0.23 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.inspircd.org/2016/09/03/v2023-released.html");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/09/05/8");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("ircd.nasl");
  script_require_ports("Services/irc", 6667);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

ircport = get_kb_item("Services/irc");
if(!ircport) ircport = 6667;

if(! get_port_state(ircport)) exit(0);

if(!banner = get_kb_item(string("irc/banner/", ircport))){
  exit(0);
}

if("InspIRCd" >!< banner)exit(0);

ircver = eregmatch(pattern:"InspIRCd-([0-9.]+)", string: banner);

if(ircver[1])
{
  if(version_is_less(version:ircver[1], test_version:"2.0.23"))
  {
    report = report_fixed_ver(installed_version:ircver[1], fixed_version: "2.0.23");
    security_message(data:report, port:ircport);
    exit( 0 );
  }
}
