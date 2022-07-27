# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106237");
  script_version("2021-09-22T07:23:44+0000");
  script_tag(name:"last_modification", value:"2021-09-22 10:15:34 +0000 (Wed, 22 Sep 2021)");
  script_tag(name:"creation_date", value:"2016-09-09 11:33:30 +0700 (Fri, 09 Sep 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("SSL/TLS: Certificate In Chain Expired");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SSL and TLS");
  script_dependencies("gb_ssl_tls_cert_chain_get.nasl");
  script_mandatory_keys("ssl_tls/port", "ssl_tls/cert_chain/extracted");

  script_tag(name:"summary", value:"The remote service is using a SSL/TLS certificate chain where
  one or multiple CA certificates have expired.");

  script_tag(name:"vuldetect", value:"Checks the expire date of the CA certificates.");

  script_tag(name:"insight", value:"Checks if the CA certificates in the SSL/TLS certificate chain
  have expired.");

  script_tag(name:"solution", value:"Sign your server certificate with a valid CA certificate.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("byte_func.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

function check_validity(port, now) {

  if (!port)
    return;

  expired = make_list();

  if (!c = get_kb_list("ssl_tls/cert_chain/" + port + "/chain"))
    exit(0);

  foreach f(c) {

    f = base64_decode(str: f);

    if (!certobj = cert_open(f))
      continue;

    expire_date = cert_query(certobj, "not-after");
    if (expire_date < now) {
      subject = cert_query(certobj, "subject");
      expired = make_list(expired, subject + '>##<' + expire_date);
    }
  }

  if (max_index(expired) > 0)
    return expired;

  return;
}

if (!port = tls_ssl_get_port())
  exit(0);

now = isotime_now();
if (strlen(now) <= 0)
  exit(0); # isotime_now: "If the current time is not available an empty string is returned."

if (ret = check_validity(port: port, now: now)) {
  foreach a (ret) {
    exp = split(a, sep: ">##<", keep: FALSE);

    subj = exp[0];
    exp_date = exp[1];

    report_expired += 'Subject:     ' + subj + '\nExpired on:  ' + isotime_print(exp_date) + '\n\n';
  }

  report = 'The following certificates which are part of the certificate chain have expired:\n\n' +
           report_expired;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);