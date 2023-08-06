# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104827");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-10 08:27:07 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-17786", "CVE-2022-32993");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("D-Link / TOTOLINK Devices 'ExportSettings.sh' Broken Access Control Vulnerability - Active Check");

  # nb: Direct access, especially to a ".sh" based file might be already seen as an attack...
  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl", "os_detection.nasl");
  # nb: No "more" specific mandatory keys because there might be different (branded) devices/vendors
  # affected as well...
  script_mandatory_keys("Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://xz.aliyun.com/t/2834");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/51556");

  script_tag(name:"summary", value:"Various D-Link and TOTOLINK devices are prone to a broken access
  control vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The security vulnerability is known as 'Unauthenticated access
  to settings' or 'Unauthenticated configuration download'. This vulnerability occurs when a device,
  such as a repeater, allows the download of user settings without requiring proper
  authentication.");

  script_tag(name:"impact", value:"Successful exploitation would give an attacker access to a
  settings file / export which might contain sensitive data like e.g. user passwords or similar.");

  script_tag(name:"affected", value:"The following devices are known to be affected:

  - CVE-2018-17786: D-Link DIR-923G with hardware version A1 and firmware version 1.02B03

  - CVE-2022-32993: TOTOLINK A7000R with firmware version 4.1cu.4134

  - No CVE: D-Link DAP-1325 with hardware version A1 and firmware version 1.01

  - No CVE: D-Link DAP-1610 and DAP-1530 / TOTOLINK N600R (in unknown versions) as determined by the
  Greenbone Security Research Team

  Other devices, versions and/or vendors might be affected as well.");

  # nb: CVE-2018-17786 would be "WillNotFix" but the flaw without a CVE might receive a fix...
  script_tag(name:"solution", value:"No known solution is available as of 10th July, 2023.
  Information regarding this issue will be updated once solution details are available.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

url = "/cgi-bin/ExportSettings.sh";

res = http_get_cache( port:port, item:url );
if( ! res || res !~ "^HTTP/1\.[01] 200" )
  exit( 0 );

headers = http_extract_headers_from_response( data:res );
if( ! headers || ! egrep( string:headers, pattern:"^[Cc]ontent-[Tt]ype\s*:\s*application/octet-stream", icase:FALSE ) )
  exit( 0 );

# D-Link DIR-823G:
# - From a screenshot on the research advisory: Content-Disposition: attachment; filename="D-Link-DIR-823G-20160218-backup.dat"
# - When accessing the script directly: Content-Disposition: attachment; filename="--20230710-backup.dat"
# D-Link DAP-1325: Content-Disposition: attachment; filename="RT2880_Settings.dat"
# D-Link DAP-1610 and DAP-1530: Content-Disposition: attachment; filename="config.bin"
# TOTOLINK N600R: Content-Disposition: attachment; filename="config.dat"
# TOTOLINK A7000R: Content-Disposition: attachment; filename="Config--20230710.dat"
pattern = '^[Cc]ontent-[Dd]isposition\\s*:\\s*attachment; filename="[^"]+\\.(dat|bin)"';

if( concl = egrep( pattern:pattern, string:headers, icase:FALSE ) ) {
  concl = chomp( concl );
  report = http_report_vuln_url( port:port, url:url );
  report += '\nConfirmation via: ' + concl;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
