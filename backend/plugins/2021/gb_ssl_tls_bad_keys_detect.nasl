# Copyright (C) 2021 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147122");
  script_version("2021-11-12T03:03:36+0000");
  script_tag(name:"last_modification", value:"2021-11-12 11:32:18 +0000 (Fri, 12 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-10 02:22:55 +0000 (Wed, 10 Nov 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-12 15:56:00 +0000 (Tue, 12 Sep 2017)");

  script_cve_id("CVE-2015-6358", "CVE-2015-7255", "CVE-2015-7256", "CVE-2015-7276", "CVE-2015-8251",
                "CVE-2015-8260");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("SSL/TLS: Known Compromised Certificate Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SSL and TLS");
  script_dependencies("ssl_cert_details.nasl");
  script_mandatory_keys("ssl/cert/avail", "ssl_tls/port");

  script_tag(name:"summary", value:"The remote SSL/TLS service is using an SSL/TLS certificate which
  is known to be compromised (e.g. known private keys, used by malware, etc).");

  script_tag(name:"vuldetect", value:"The script checks the SSL/TLS SHA-1 fingerprint of the SSL/TLS
  certificate of the remote SSL/TLS service against a list of known compromised ones.");

  script_tag(name:"impact", value:"An attacker could use this for man-in-the-middle (MITM) attacks,
  accessing sensible data and other attacks.");

  script_tag(name:"affected", value:"A wide range of devices from vendors like Actiontec, Cisco,
  D-Link Systems, General Electric, Huawei Technologies, NetComm Wireless Limited, Sierra Wireless,
  Technicolor, Ubiquiti Networks, ZTE Corporation and ZyXEL are known to be affected.");

  script_tag(name:"solution", value:"Replace the SSL/TLS certificate with a trusted/clean one.");

  script_xref(name:"URL", value:"https://www.fireeye.com/blog/threat-research/2013/03/md5-sha1.html");
  script_xref(name:"URL", value:"https://www.fireeye.com/blog/threat-research/2017/06/behind-the-carbanak-backdoor.html");
  script_xref(name:"URL", value:"http://code.google.com/p/littleblackbox/");
  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/566724");
  script_xref(name:"URL", value:"https://github.com/sec-consult/houseofkeys");

  exit(0);
}

include("byte_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("mysql.inc");
include("ssl_tls_bad_fingerprints.inc");
include("ssl_funcs.inc");

if (!port = tls_ssl_get_port())
  exit(0);

cert = get_server_cert(port: port);

bad_keys = make_list_unique(ssl_bad_fingerprints);

if (cert) {
  obj = cert_open(cert);
  if (!obj)
    exit(0);

  fingerprint = cert_query(obj, "fpr-sha-1");
  cert_close(obj);
  if (!fingerprint)
    exit(99);

  if (in_array(search: fingerprint, array: bad_keys, part_match: FALSE)) {
    key = get_kb_item("HostDetails/SSLInfo/" + port);
    report = 'The following SSL/TLS certificate is known to be compromised:\n' +
             cert_summary(key: "HostDetails/Cert/" + key + "/");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
