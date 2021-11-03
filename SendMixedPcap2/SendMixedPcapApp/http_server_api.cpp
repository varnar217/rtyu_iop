#include "Global.h"
#include "Log.h"
#include "DateTime.h"
#include "common.h"
#include "http_server_api.h"

#if USE_JSON_OPTION == USE_JSON_NLOHMANN
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif

/*------------------------------------------------------------------------------
завершить работу приложения ядра

ЗАПРОС (REQUEST): DELETE(/exit):
-

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_delete_exit_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_delete_exit_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
первоначальное подключение интерфейса к ядру и получение от ядра его параметров и состояния

ЗАПРОС (REQUEST): GET(/init?addr=&port=):
-

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "state": {
    "run": bool
  },
  "params": {
    "mode": number,
    "br": number,
    "ipsrc": string,
    "ipdst": string,
    "file": {
      "path": string,
      "size": number
    },
    "gtp": {
      "use": bool,
      "ipsrc": string,
      "ipdst": string,
      "minteid": number,
      "maxteid": number
    },
    "service": [ {
      "id": number,
      "name": string
		},
    "app": [ {
      "id": number,
      "name": string
		},
    "pcap": [ {
      "id": number,
      "video": bool,
      "service": {
        "id": number
       },
      "app": {
        "id": number
       },
      "br": number,
      "path": string
    } ],
    "user_scenario": [ { 
      "id": number,
      "name": string,
      "br": number,
      "pcap_id": [
        number
      ]
    } ],
    "network_scenario": [ {
      "id": number,
      "name": string,
      "jitter": {
        "timeup": number,
        "timedown": number,
        "value": number
      },
      "burst": {
        "timeup": number,
        "timedown": number
      }
    } ],
    "eb": [ {
      "id": number,
      "br": number,
      "user_scenario": {
        "id": number,
        "name": string,
        "br": number,
        "pcap_id": [
          number
      },
      "network_scenario": {
        "id": number,
        "name": string,
        "jitter": {
          "timeup": number,
          "timedown": number,
          "value": number
        },
        "burst": {
          "timeup": number,
          "timedown": number
        }
      }
    } ]
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_get_init_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-01T18:25:43.511Z"
  },
  "state": {
    "run": true
  },
  "params": {
    "mode": 0,
    "br": 10000000000,
    "ipsrc": "192.168.1.11",
    "ipdst": "192.168.1.22",
    "file": {
      "path": "/home/user/store",
      "size": 1024
    },
    "gtp": {
      "use": false,
      "ipsrc": "192.168.1.111",
      "ipdst": "192.168.1.222",
      "minteid": 1,
      "maxteid": 500
    },
    "service": [ {
      "id": 1,
      "name": "Видео соцсеть"
      }, {
      "id": 2,
      "name": "Видео мессенджер"
      }, {
      "id": 3,
      "name": "Видео хостинг"
      }, {
      "id": 4,
      "name": "Аудио"
      }, {
      "id": 5,
      "name": "Фоновый шум"
      }
    ],
    "app": [ {
      "id": 1,
      "name": "Instagram"
      }, {
      "id": 2,
      "name": "Whatsapp"
      }, {
      "id": 3,
      "name": "Youtube"
      }, {
      "id": 4,
      "name": "Shazaam"
      }, {
      "id": 5,
      "name": "Разные"
      }
    ],
    "pcap": [ {
      "id": 1,
      "video": true,
      "service": {
        "id": 1
       },
      "app": {
        "id": 1
       },
      "br": 10000000,
      "path": "/home/user/pcap/video/social/instagram_10mbps.pcap"
    }, {
      "id": 2,
      "video": true,
      "service": {
        "id": 2
       },
      "app": {
        "id": 2
       },
      "br": 5000000,
      "path": "/home/user/pcap/video/messenger/whatsapp_5mbps.pcap"
    }, {
      "id": 3,
      "video": true,
      "service": {
        "id": 3
       },
      "app": {
        "id": 3
       },
      "br": 20000000,
      "path": "/home/user/pcap/video/hosting/youtube_20mbps.pcap"
    }, {
      "id": 4,
      "video": false,
      "service": {
        "id": 4
       },
      "app": {
        "id": 4
       },
      "br": 500000,
      "path": "/home/user/pcap/audio/shazaam_500kbps.pcap"
    }, {
      "id": 5,
      "video": false,
      "service": {
        "id": 5
       },
      "app": {
        "id": 5
       },
      "br": 100000,
      "path": "/home/user/pcap/noise/noise_100kbps.pcap"
    } ],
    "user_scenario": [ { 
      "id": 1,
      "name": "Social media",
      "br": 40000000,
      "pcap_id": [
        1, 2
      ]
    }, { 
      "id": 2,
      "name": "Co-working",
      "br": 30000000,
      "pcap_id": [
        2, 5
      ]
    }, { 
      "id": 3,
      "name": "Movie",
      "br": 50000000,
      "pcap_id": [
        3, 5
      ]
    } ],
    "network_scenario": [ {
      "id": 1,
      "name": "No change",
      "jitter": {
        "timeup": 1000,
        "timedown": 0,
        "value": 500
      },
      "burst": {
        "timeup": 5000,
        "timedown": 5000
      }
    }, {
      "id": 2,
      "name": "Low delay",
      "jitter": {
        "timeup": 1000,
        "timedown": 500,
        "value": 1000
      },
      "burst": {
        "timeup": 6000,
        "timedown": 4000
      }
    } ],
    "eb": [ {
      "id": 1,
      "br": 40000000,
      "user_scenario": {
        "id": 1
      },
      "network_scenario": {
        "id": 1
      }
    }, {
      "id": 2,
      "br": 50000000,
      "user_scenario": {
        "id": 3
      },
      "network_scenario": {
        "id": 2
      }
    }, {
      "id": 3,
      "br": 30000000,
      "user_scenario": {
        "id": 0,
        "name": "Custom",
        "br": 9000000,
        "pcap_id": [
          1, 2
        ] },
      "network_scenario": {
        "id": 0,
        "name": "Custom",
        "jitter": {
          "timeup": 1000,
          "timedown": 0,
          "value": 500
        },
        "burst": {
          "timeup": 5000,
          "timedown": 5000
        }
      }
    } ]
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_get_init_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
получить состояние работы ядра

ЗАПРОС (REQUEST): GET(/state):
-

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "state": {
    "run": bool
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_get_state_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "state": {
    "run": false
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_get_state_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
изменить состояние (запустить или остановить) работы ядра

ЗАПРОС (REQUEST): PUT(/state/run):
{
  "state": {
    "run": bool
  }
}

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "state": {
    "run": bool
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
2 - Ядро ГТО уже выполняется
3 - Ядро ГТО уже остановлено
*/

//ПРИМЕР ЗАПРОСА:
const char* json_request_put_state_run = R"(
{
  "state": {
    "run": true
  }
}
)";

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_put_state_run_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "state": {
    "run": true
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_put_state_run_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  },
  "state": {
    "run": true
  }
}
)";

/*------------------------------------------------------------------------------
получить статистику по всем EPS-Bearer

ЗАПРОС (REQUEST): GET(/stats/eb):

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "stats": {
    "eb_id": number,
    "time": string,
    "period": number,
    "size": number,
    "vpercent": number,
    "avrpktsz": number,
    "pktcount": number
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_get_stats_eb_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "stats": {
    "eb_id": 1,
    "time": "2021-10-06T04:34:21.1436",
    "period": 1000,
    "size": 35000000,
    "vpercent": 82,
    "avrpktsz": 1352,
    "pktcount": 3700
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_get_stats_eb_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
получить статистику по EPS-Bearer с идентификатором N

ЗАПРОС (REQUEST): GET(/stats/eb/N):

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "stats": {
    "eb_id": number,
    "time": string,
    "period": number,
    "size": number,
    "vpercent": number,
    "avrpktsz": number,
    "pktcount": number
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_get_stats_eb_n_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "stats": {
    "eb_id": 1,
    "time": "2021-10-06T04:34:21.1436",
    "period": 1000,
    "size": 35000000,
    "vpercent": 82,
    "avrpktsz": 1352,
    "pktcount": 3700
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_get_stats_eb_n_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
получить все параметры работы ядра

ЗАПРОС (REQUEST): GET(/params):
-

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "params": {
    "mode": number,
    "br": number,
    "file": {
      "path": string,
      "size": number
    },
    "gtp": {
      "use": bool,
      "ipsrc": string,
      "ipdst": string,
      "minteid": number,
      "maxteid": number
    },
    "pcap": [ {
      "id": number,
      "video": bool,
      "service": {
        "id": number
       },
      "app": {
        "id": number
       },
      "br": number,
      "path": string
    } ],
    "user_scenario": [ { 
      "id": number,
      "name": string,
      "br": number,
      "pcap_id": [
        "id": number
      ]
    } ],
    "network_scenario": [ {
      "id": number,
      "name": string,
      "jitter": {
        "timeup": number,
        "timedown": number,
        "value": number
      },
      "burst": {
        "timeup": number,
        "timedown": number
      }
    } ],
    "eb": [ {
      "id": number,
      "br": number,
      "user_scenario": { 
        "id": number,
        "name": string,
        "br": number,
       "pcap_id": [
          "id": number
        ]
      },
      "network_scenario": {
        "id": number,
        "name": string,
        "jitter": {
          "timeup": number,
          "timedown": number,
          "value": number
        },
        "burst": {
          "timeup": number,
          "timedown": number
        }
      }
    } ]
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_get_params_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "mode": 0,
    "br": 10000000000,
    "file": {
      "path": "/home/user/store",
      "size": 1024
    },
    "gtp": {
      "use": false,
      "ipsrc": "192.168.1.111",
      "ipdst": "192.168.1.222",
      "minteid": 1,
      "maxteid": 500
    },
    "pcap": [ {
      "id": 1,
      "video": true,
      "service": {
        "id": 1
       },
      "app": {
        "id": 1
       },
      "br": 10000000,
      "path": "/home/user/pcap/video/social/instagram_10mbps.pcap"
    }, {
      "id": 2,
      "video": true,
      "service": {
        "id": 2
       },
      "app": {
        "id": 2
       },
      "br": 5000000,
      "path": "/home/user/pcap/video/messenger/whatsapp_5mbps.pcap"
    }, {
      "id": 3,
      "video": true,
      "service": {
        "id": 3
       },
      "app": {
        "id": 3
       },
      "br": 20000000,
      "path": "/home/user/pcap/video/hosting/youtube_20mbps.pcap"
    }, {
      "id": 4,
      "video": false,
      "service": {
        "id": 4
       },
      "app": {
        "id": 4
       },
      "br": 500000,
      "path": "/home/user/pcap/audio/shazaam_500kbps.pcap"
    }, {
      "id": 5,
      "video": false,
      "service": {
        "id": 5
       },
      "app": {
        "id": 5
       },
      "br": 100000,
      "path": "/home/user/pcap/noise/noise_100kbps.pcap"
    } ],
    "user_scenario": [ { 
      "id": 1,
      "name": "Social media",
      "br": 40000000,
     "pcap_id": [
        1, 2
      ]
    }, { 
      "id": 2,
      "name": "Co-working",
      "br": 30000000,
     "pcap_id": [
        2, 5
      ]
    }, { 
      "id": 3,
      "name": "Movie",
      "br": 50000000,
     "pcap_id": [
        3, 5
      ]
    } ],
    "network_scenario": [ {
      "id": 1,
      "name": "No change",
      "jitter": {
        "timeup": 1000,
        "timedown": 0,
        "value": 500
      },
      "burst": {
        "timeup": 5000,
        "timedown": 5000
      }
    }, {
      "id": 2,
      "name": "Low delay",
      "jitter": {
        "timeup": 1000,
        "timedown": 0,
        "value": 500
      },
      "burst": {
        "timeup": 5000,
        "timedown": 5000
      }
    } ],
    "eb": [ {
      "id": 1,
      "br": 40000000,
      "user_scenario": {
        "id": 1
      },
      "network_scenario": {
        "id": 1
      }
    }, {
      "id": 2,
      "br": 50000000,
      "user_scenario": {
        "id": 3
      },
      "network_scenario": {
        "id": 2
      }
    }, {
      "id": 3,
      "br": 30000000,
      "user_scenario": {
        "id": 0,
        "name": "Custom",
        "br": 9000000,
        "pcap_id": [
          1, 2
        ] },
      "network_scenario": {
        "id": 0,
        "name": "Custom",
        "jitter": {
          "timeup": 1000,
          "timedown": 0,
          "value": 500
        },
        "burst": {
          "timeup": 5000,
          "timedown": 5000
        }
      }
    } ]
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_get_params_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
изменить параметры работы ядра

ЗАПРОС (REQUEST): PUT(/params):
{
  "params": {
    "mode": number,
    "br": number,
    "ipsrc": string,
    "ipdst": string,
    "file": {
      "path": string,
      "size": number
    },
    "gtp": {
      "use": bool,
      "ipsrc": string,
      "ipdst": string,
      "minteid": number,
      "maxteid": number
    },
    "pcap": [ {
      "id": number,
      "video": bool,
      "service": {
        "id": number
       },
      "app": {
        "id": number
       },
      "br": number,
      "path": string
    } ],
    "user_scenario": [ { 
      "id": number,
      "name": string,
      "br": number,
     "pcap_id": [
        "id": number
      ]
    } ],
    "network_scenario": [ {
      "id": number,
      "name": string,
      "jitter": {
        "timeup": number,
        "timedown": number,
        "value": number
      },
      "burst": {
        "timeup": number,
        "timedown": number
      }
    } ],
    "eb": [ {
      "id": number,
      "br": number,
      "user_scenario": { 
        "id": number,
        "name": string,
        "br": number,
       "pcap_id": [
          "id": number
        ]
      },
      "network_scenario": {
        "id": number,
        "name": string,
        "jitter": {
          "timeup": number,
          "timedown": number,
          "value": number
        },
        "burst": {
          "timeup": number,
          "timedown": number
        }
      }
    } ]
  }
}

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "params": {
    "mode": number,
    "br": number,
    "ipsrc": string,
    "ipdst": string,
    "file": {
      "path": string,
      "size": number
    },
    "gtp": {
      "use": bool,
      "ipsrc": string,
      "ipdst": string,
      "minteid": number,
      "maxteid": number
    },
    "pcap": [ {
      "id": number,
      "video": bool,
      "service": {
        "id": number
       },
      "app": {
        "id": number
       },
      "br": number,
      "path": string
    } ],
    "user_scenario": [ { 
      "id": number,
      "name": string,
      "br": number,
     "pcap_id": [
        "id": number
      ]
    } ],
    "network_scenario": [ {
      "id": number,
      "name": string,
      "jitter": {
        "timeup": number,
        "timedown": number,
        "value": number
      },
      "burst": {
        "timeup": number,
        "timedown": number
      }
    } ],
    "eb": [ {
      "id": number,
      "br": number,
      "user_scenario": { 
        "id": number,
        "name": string,
        "br": number,
       "pcap_id": [
          "id": number
        ]
      },
      "network_scenario": {
        "id": number,
        "name": string,
        "jitter": {
          "timeup": number,
          "timedown": number,
          "value": number
        },
        "burst": {
          "timeup": number,
          "timedown": number
        }
      }
    } ]
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР ЗАПРОСА:
const char* json_request_put_params = R"(
{
  "params": {
    "mode": 0,
    "br": 10000000000,
      "ipsrc": "192.168.1.11",
      "ipdst": "192.168.1.22",
    "file": {
      "path": "/home/user/store",
      "size": 1024
    },
    "gtp": {
      "use": false,
      "ipsrc": "192.168.1.111",
      "ipdst": "192.168.1.222",
      "minteid": 1,
      "maxteid": 500
    },
    "pcap": [ {
      "id": 1,
      "video": true,
      "service": {
        "id": 1
       },
      "app": {
        "id": 1
       },
      "br": 10000000,
      "path": "/home/user/pcap/video/social/instagram_10mbps.pcap"
    }, {
      "id": 2,
      "video": true,
      "service": {
        "id": 2
       },
      "app": {
        "id": 2
       },
      "br": 5000000,
      "path": "/home/user/pcap/video/messenger/whatsapp_5mbps.pcap"
    }, {
      "id": 3,
      "video": true,
      "service": {
        "id": 3
       },
      "app": {
        "id": 3
       },
      "br": 20000000,
      "path": "/home/user/pcap/video/hosting/youtube_20mbps.pcap"
    }, {
      "id": 4,
      "video": false,
      "service": {
        "id": 4
       },
      "app": {
        "id": 4
       },
      "br": 500000,
      "path": "/home/user/pcap/audio/shazaam_500kbps.pcap"
    }, {
      "id": 5,
      "video": false,
      "service": {
        "id": 5
       },
      "app": {
        "id": 5
       },
      "br": 100000,
      "path": "/home/user/pcap/noise/noise_100kbps.pcap"
    } ],
    "user_scenario": [ { 
      "id": 1,
      "name": "Social media",
      "br": 40000000,
     "pcap_id": [
        1, 2
      ]
    }, { 
      "id": 2,
      "name": "Co-working",
      "br": 30000000,
     "pcap_id": [
        2, 5
      ]
    }, { 
      "id": 3,
      "name": "Movie",
      "br": 50000000,
     "pcap_id": [
        3, 5
      ]
    } ],
    "network_scenario": [ {
      "id": 1,
      "name": "No change",
      "jitter": {
        "timeup": 1000,
        "timedown": 0,
        "value": 500
      },
      "burst": {
        "timeup": 5000,
        "timedown": 5000
      }
    }, {
      "id": 2,
      "name": "Low delay",
      "jitter": {
        "timeup": 1000,
        "timedown": 0,
        "value": 500
      },
      "burst": {
        "timeup": 5000,
        "timedown": 5000
      }
    } ],
    "eb": [ {
      "id": 1,
      "br": 40000000,
      "user_scenario": {
        "id": 1
      },
      "network_scenario": {
        "id": 1
      }
    }, {
      "id": 2,
      "br": 50000000,
      "user_scenario": {
        "id": 3
      },
      "network_scenario": {
        "id": 2
      }
    }, {
      "id": 3,
      "br": 30000000,
      "user_scenario": {
        "id": 0,
        "name": "Custom",
        "br": 9000000,
        "pcap_id": [
          1, 2
        ] },
      "network_scenario": {
        "id": 0,
        "name": "Custom",
        "jitter": {
          "timeup": 1000,
          "timedown": 0,
          "value": 500
        },
        "burst": {
          "timeup": 5000,
          "timedown": 5000
        }
      }
    } ]
  }
}
)";

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_put_params_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "mode": 0,
    "br": 10000000000,
    "ipsrc": "192.168.1.11",
    "ipdst": "192.168.1.22",
    "file": {
      "path": "/home/user/store",
      "size": 1024
    },
    "gtp": {
      "use": false,
      "ipsrc": "192.168.1.111",
      "ipdst": "192.168.1.222",
      "minteid": 1,
      "maxteid": 500
    },
    "pcap": [ {
      "id": 1,
      "video": true,
      "service": {
        "id": 1
       },
      "app": {
        "id": 1
       },
      "br": 10000000,
      "path": "/home/user/pcap/video/social/instagram_10mbps.pcap"
    }, {
      "id": 2,
      "video": true,
      "service": {
        "id": 2
       },
      "app": {
        "id": 2
       },
      "br": 5000000,
      "path": "/home/user/pcap/video/messenger/whatsapp_5mbps.pcap"
    }, {
      "id": 3,
      "video": true,
      "service": {
        "id": 3
       },
      "app": {
        "id": 3
       },
      "br": 20000000,
      "path": "/home/user/pcap/video/hosting/youtube_20mbps.pcap"
    }, {
      "id": 4,
      "video": false,
      "service": {
        "id": 4
       },
      "app": {
        "id": 4
       },
      "br": 500000,
      "path": "/home/user/pcap/audio/shazaam_500kbps.pcap"
    }, {
      "id": 5,
      "video": false,
      "service": {
        "id": 5
       },
      "app": {
        "id": 5
       },
      "br": 100000,
      "path": "/home/user/pcap/noise/noise_100kbps.pcap"
    } ],
    "user_scenario": [ { 
      "id": 1,
      "name": "Social media",
      "br": 40000000,
     "pcap_id": [
        1, 2
      ]
    }, { 
      "id": 2,
      "name": "Co-working",
      "br": 30000000,
     "pcap_id": [
        2, 5
      ]
    }, { 
      "id": 3,
      "name": "Movie",
      "br": 50000000,
     "pcap_id": [
        3, 5
      ]
    } ],
    "network_scenario": [ {
      "id": 1,
      "name": "No change",
      "jitter": {
        "timeup": 1000,
        "timedown": 0,
        "value": 500
      },
      "burst": {
        "timeup": 5000,
        "timedown": 5000
      }
    }, {
      "id": 2,
      "name": "Low delay",
      "jitter": {
        "timeup": 1000,
        "timedown": 0,
        "value": 500
      },
      "burst": {
        "timeup": 5000,
        "timedown": 5000
      }
    } ],
    "eb": [ {
      "id": 1,
      "br": 40000000,
      "user_scenario": {
        "id": 1
      },
      "network_scenario": {
        "id": 1
      }
    }, {
      "id": 2,
      "br": 50000000,
      "user_scenario": {
        "id": 3
      },
      "network_scenario": {
        "id": 2
      }
    }, {
      "id": 3,
      "br": 30000000,
      "user_scenario": {
        "id": 0,
        "name": "Custom",
        "br": 9000000,
        "pcap_id": [
          1, 2
        ] },
      "network_scenario": {
        "id": 0,
        "name": "Custom",
        "jitter": {
          "timeup": 1000,
          "timedown": 0,
          "value": 500
        },
        "burst": {
          "timeup": 5000,
          "timedown": 5000
        }
      }
    } ]
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_put_params_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "mode": 0,
    "br": 10000000000,
    "ipsrc": "192.168.1.11",
    "ipdst": "192.168.1.22",
    "file": {
      "path": "/home/user/store",
      "size": 1024
    },
    "gtp": {
      "use": false,
      "ipsrc": "192.168.1.111",
      "ipdst": "192.168.1.222",
      "minteid": 1,
      "maxteid": 500
    },
    "pcap": [ {
      "id": 1,
      "video": true,
      "service": {
        "id": 1
       },
      "app": {
        "id": 1
       },
      "br": 10000000,
      "path": "/home/user/pcap/video/social/instagram_10mbps.pcap"
    }, {
      "id": 2,
      "video": true,
      "service": {
        "id": 2
       },
      "app": {
        "id": 2
       },
      "br": 5000000,
      "path": "/home/user/pcap/video/messenger/whatsapp_5mbps.pcap"
    }, {
      "id": 3,
      "video": true,
      "service": {
        "id": 3
       },
      "app": {
        "id": 3
       },
      "br": 20000000,
      "path": "/home/user/pcap/video/hosting/youtube_20mbps.pcap"
    }, {
      "id": 4,
      "video": false,
      "service": {
        "id": 4
       },
      "app": {
        "id": 4
       },
      "br": 500000,
      "path": "/home/user/pcap/audio/shazaam_500kbps.pcap"
    }, {
      "id": 5,
      "video": false,
      "service": {
        "id": 5
       },
      "app": {
        "id": 5
       },
      "br": 100000,
      "path": "/home/user/pcap/noise/noise_100kbps.pcap"
    } ],
    "user_scenario": [ { 
      "id": 1,
      "name": "Social media",
      "br": 40000000,
     "pcap_id": [
        1, 2
      ]
    }, { 
      "id": 2,
      "name": "Co-working",
      "br": 30000000,
     "pcap_id": [
        2, 5
      ]
    }, { 
      "id": 3,
      "name": "Movie",
      "br": 50000000,
     "pcap_id": [
        3, 5
      ]
    } ],
    "network_scenario": [ {
      "id": 1,
      "name": "No change",
      "jitter": {
        "timeup": 1000,
        "timedown": 0,
        "value": 500
      },
      "burst": {
        "timeup": 5000,
        "timedown": 5000
      }
    }, {
      "id": 2,
      "name": "Low delay",
      "jitter": {
        "timeup": 1000,
        "timedown": 0,
        "value": 500
      },
      "burst": {
        "timeup": 5000,
        "timedown": 5000
      }
    } ],
    "eb": [ {
      "id": 1,
      "br": 40000000,
      "user_scenario": {
        "id": 1
      },
      "network_scenario": {
        "id": 1
      }
    }, {
      "id": 2,
      "br": 50000000,
      "user_scenario": {
        "id": 3
      },
      "network_scenario": {
        "id": 2
      }
    }, {
      "id": 3,
      "br": 30000000,
      "user_scenario": {
        "id": 0,
        "name": "Custom",
        "br": 9000000,
        "pcap_id": [
          1, 2
        ] },
      "network_scenario": {
        "id": 0,
        "name": "Custom",
        "jitter": {
          "timeup": 1000,
          "timedown": 0,
          "value": 500
        },
        "burst": {
          "timeup": 5000,
          "timedown": 5000
        }
      }
    } ]
  }
}
)";

/*------------------------------------------------------------------------------
получить "общие" параметры работы ядра (режим работы, суммарный битрейт, GTP, файл сохранения)

ЗАПРОС (REQUEST): GET(/params/common):
-

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "params": {
    "mode": number,
    "br": number,
    "ipsrc": string,
    "ipdst": string,
    "file": {
      "path": string,
      "size": number
    },
    "gtp": {
      "use": bool,
      "ipsrc": string,
      "ipdst": string,
      "minteid": number,
      "maxteid": number
    }
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_get_params_common_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "mode": 0,
    "br": 10000000000,
    "ipsrc": "192.168.1.11",
    "ipdst": "192.168.1.22",
    "file": {
      "path": "/home/user/store",
      "size": 1024
    },
    "gtp": {
      "use": false,
      "ipsrc": "192.168.1.111",
      "ipdst": "192.168.1.222",
      "minteid": 1,
      "maxteid": 500
    }
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_get_params_common_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
изменить "общие" параметры работы ядра (режим работы, суммарный битрейт, GTP, файл сохранения)

ЗАПРОС (REQUEST): PUT(/params/common):
{
  "params": {
    "mode": number,
    "br": number,
    "ipsrc": string,
    "ipdst": string,
    "file": {
      "path": string,
      "size": number
    },
    "gtp": {
      "use": bool,
      "ipsrc": string,
      "ipdst": string,
      "minteid": number,
      "maxteid": number
    }
  }
}

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "params": {
    "mode": number,
    "br": number,
    "ipsrc": string,
    "ipdst": string,
    "file": {
      "path": string,
      "size": number
    },
    "gtp": {
      "use": bool,
      "ipsrc": string,
      "ipdst": string,
      "minteid": number,
      "maxteid": number
    }
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР ЗАПРОСА:
const char* json_request_put_params_common = R"(
{
  "params": {
    "mode": 0,
    "br": 10000000000,
    "ipsrc": "192.168.1.11",
    "ipdst": "192.168.1.22",
    "file": {
      "path": "/home/user/store",
      "size": 1024
    },
    "gtp": {
      "use": false,
      "ipsrc": "192.168.1.111",
      "ipdst": "192.168.1.222",
      "minteid": 1,
      "maxteid": 500
    }
  }
}
)";

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_put_params_common_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "mode": 0,
    "br": 10000000000,
    "ipsrc": "192.168.1.11",
    "ipdst": "192.168.1.22",
    "file": {
      "path": "/home/user/store",
      "size": 1024
    },
    "gtp": {
      "use": false,
      "ipsrc": "192.168.1.111",
      "ipdst": "192.168.1.222",
      "minteid": 1,
      "maxteid": 500
    }
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_put_params_common_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "mode": 0,
    "br": 10000000000,
    "file": {
      "path": "/home/user/store",
      "size": 1024
    },
    "gtp": {
      "use": false,
      "ipsrc": "192.168.1.111",
      "ipdst": "192.168.1.222",
      "minteid": 1,
      "maxteid": 500
    }
  }
}
)";

/*------------------------------------------------------------------------------
получить список всех сервисов возможных в PCAP файле

ЗАПРОС (REQUEST): GET(/params/service):
-

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "params": {
    "service": [ {
      "id": number,
      "name": string
      }
    ]
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_get_params_service_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "service": [ {
      "id": 1,
      "name": "Видео соцсеть"
      }, {
      "id": 2,
      "name": "Видео мессенджер"
      }, {
      "id": 3,
      "name": "Видео хостинг"
      }, {
      "id": 4,
      "name": "Аудио"
      }, {
      "id": 5,
      "name": "Фоновый шум"
      }
    ]
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_get_params_service_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
получить список всех приложений возможных в PCAP файле

ЗАПРОС (REQUEST):  GET(/params/app):
-

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "params": {
    "app": [ {
      "id": number,
      "name": string
      }
    ]
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_get_params_app_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "app": [ {
      "id": 1,
      "name": "Instagram"
      }, {
      "id": 2,
      "name": "Whatsapp"
      }, {
      "id": 3,
      "name": "Youtube"
      }, {
      "id": 4,
      "name": "Shazaam"
      }, {
      "id": 5,
      "name": "Разные"
      }
    ]
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_get_params_app_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
получить список всех PCAP файлов доступных ядру

ЗАПРОС (REQUEST): GET(/params/pcap):
-

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "params": {
    "pcap": [ {
      "id": number,
      "video": bool,
      "service": {
        "id": number
       },
      "app": {
        "id": number
       },
      "br": number,
      "path": string
    } ]
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_get_params_pcap_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "pcap": [ {
      "id": 1,
      "video": true,
      "service": {
        "id": 1
       },
      "app": {
        "id": 1
       },
      "br": 10000000,
      "path": "/home/user/pcap/video/social/instagram_10mbps.pcap"
    }, {
      "id": 2,
      "video": true,
      "service": {
        "id": 2
       },
      "app": {
        "id": 2
       },
      "br": 5000000,
      "path": "/home/user/pcap/video/messenger/whatsapp_5mbps.pcap"
    }, {
      "id": 3,
      "video": true,
      "service": {
        "id": 3
       },
      "app": {
        "id": 3
       },
      "br": 20000000,
      "path": "/home/user/pcap/video/hosting/youtube_20mbps.pcap"
    }, {
      "id": 4,
      "video": false,
      "service": {
        "id": 4
       },
      "app": {
        "id": 4
       },
      "br": 500000,
      "path": "/home/user/pcap/audio/shazaam_500kbps.pcap"
    }, {
      "id": 5,
      "video": false,
      "service": {
        "id": 5
       },
      "app": {
        "id": 5
       },
      "br": 100000,
      "path": "/home/user/pcap/noise/noise_100kbps.pcap"
    } ]
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_get_params_pcap_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
получить список всех сохранённых пользовательских сценариев доступных ядру

ЗАПРОС (REQUEST): GET(/params/user_scenario):
-

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "params": {
    "user_scenario": [ { 
      "id": number,
      "name": string,
      "br": number,
     "pcap_id": [
        number
      ]
    } ]
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_get_params_user_scenario_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "user_scenario": [ { 
      "id": 1,
      "name": "Social media",
      "br": 40000000,
     "pcap_id": [
        1, 2
      ]
    }, { 
      "id": 2,
      "name": "Co-working",
      "br": 30000000,
     "pcap_id": [
        2, 5
      ]
    }, { 
      "id": 3,
      "name": "Movie",
      "br": 50000000,
     "pcap_id": [
        3, 5
      ]
    } ]
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_get_params_user_scenario_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
создать один/несколько пользовательских сценариев доступных ядру

ЗАПРОС (REQUEST): POST(/params/user_scenario):
{
  "params": {
    "user_scenario": [ { 
      "id": number,
      "name": string,
      "br": number,
     "pcap_id": [
        number
      ]
    } ]
  }
}

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "params": {
    "user_scenario": [ { 
      "id": number,
      "name": string,
      "br": number,
     "pcap_id": [
        number
      ]
    } ]
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР ЗАПРОСАА:
const char* json_request_post_params_user_scenario = R"(
{
  "params": {
    "user_scenario": [ { 
      "id": 7,
      "name": "Social media",
      "br": 40000000,
     "pcap_id": [
        1, 2
      ]
    }, { 
      "id": 8,
      "name": "Co-working",
      "br": 30000000,
     "pcap_id": [
        2, 5
      ]
    } ]
  }
}
)";

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_post_params_user_scenario_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "user_scenario": [ { 
      "id": 7,
      "name": "Social media",
      "br": 40000000,
     "pcap_id": [
        1, 2
      ]
    }, { 
      "id": 8,
      "name": "Co-working",
      "br": 30000000,
     "pcap_id": [
        2, 5
      ]
    } ]
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_post_params_user_scenario_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
изменить один/несколько/все пользовательские сценарии доступные ядру

ЗАПРОС (REQUEST): PUT(/params/user_scenario):
{
  "params": {
    "user_scenario": [ { 
      "id": number,
      "name": string,
      "br": number,
     "pcap_id": [
        number
      ]
    } ]
  }
}

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "params": {
    "user_scenario": [ { 
      "id": number,
      "name": string,
      "br": number,
     "pcap_id": [
        number
      ]
    } ]
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР ЗАПРОСА:
const char* json_request_put_params_user_scenario_ok = R"(
{
  "params": {
    "user_scenario": [ { 
      "id": 1,
      "name": "Social media",
      "br": 40000000,
     "pcap_id": [
        1, 2
      ]
    }, { 
      "id": 2,
      "name": "Co-working",
      "br": 30000000,
     "pcap_id": [
        2, 5
      ]
    } ]
  }
}
)";

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_put_params_user_scenario_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "user_scenario": [ { 
      "id": 1,
      "name": "Social media",
      "br": 40000000,
     "pcap_id": [
        1, 2
      ]
    }, { 
      "id": 2,
      "name": "Co-working",
      "br": 30000000,
     "pcap_id": [
        2, 5
      ]
    } ]
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_put_params_user_scenario_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "user_scenario": [ { 
      "id": 1,
      "name": "Social media",
      "br": 40000000,
     "pcap_id": [
        1, 2
      ]
    }, { 
      "id": 2,
      "name": "Co-working",
      "br": 30000000,
     "pcap_id": [
        2, 5
      ]
    } ]
  }
}
)";

/*------------------------------------------------------------------------------
удалить один/несколько/все пользовательские сценарии доступные ядру

ЗАПРОС (REQUEST): DELETE(/params/user_scenario):
{
  "params": {
    "user_scenario": [ { 
      "id": number
    } ]
  }
}

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР ЗАПРОСА:
const char* json_request_delete_params_user_scenario = R"(
{
  "params": {
    "user_scenario": [ { 
      "id": 7
    }, { 
      "id": 8
    } ]
  }
}
)";

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_delete_params_user_scenario_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_delete_params_user_scenario_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
получить список всех сохранённых сетевых сценариев доступных ядру

ЗАПРОС (REQUEST): GET(/params/network_scenario):
-

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "params": {
    "network_scenario": [ {
      "id": number,
      "name": string,
      "jitter": {
        "timeup": number,
        "timedown": number,
        "value": number
      },
      "burst": {
        "timeup": number,
        "timedown": number
      }
    } ]
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_get_params_network_scenario_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "network_scenario": [ {
      "id": 1,
      "name": "No change",
      "jitter": {
        "timeup": 1000,
        "timedown": 0,
        "value": 500
      },
      "burst": {
        "timeup": 5000,
        "timedown": 5000
      }
    }, {
      "id": 2,
      "name": "Low delay",
      "jitter": {
        "timeup": 1000,
        "timedown": 500,
        "value": 1000
      },
      "burst": {
        "timeup": 6000,
        "timedown": 4000
      }
    } ]
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_get_params_network_scenario_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
создать один/несколько сетевых сценариев доступных ядру

ЗАПРОС (REQUEST): POST(/params/network_scenario):
{
  "params": {
    "network_scenario": [ {
      "id": number,
      "name": string,
      "jitter": {
        "timeup": number,
        "timedown": number,
        "value": number
      },
      "burst": {
        "timeup": number,
        "timedown": number
      }
    } ]
  }
}

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "params": {
    "network_scenario": [ {
      "id": number,
      "name": string,
      "jitter": {
        "timeup": number,
        "timedown": number,
        "value": number
      },
      "burst": {
        "timeup": number,
        "timedown": number
      }
    } ]
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР ЗАПРОСАА:
const char* json_request_post_params_network_scenario = R"(
{
  "params": {
    "network_scenario": [ {
      "id": 1,
      "name": "No change",
      "jitter": {
        "timeup": 1000,
        "timedown": 0,
        "value": 500
      },
      "burst": {
        "timeup": 5000,
        "timedown": 5000
      }
    }, {
      "id": 2,
      "name": "Low delay",
      "jitter": {
        "timeup": 1000,
        "timedown": 500,
        "value": 1000
      },
      "burst": {
        "timeup": 6000,
        "timedown": 4000
      }
    } ]
  }
}
)";

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_post_params_network_scenario_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "network_scenario": [ {
      "id": 1,
      "name": "No change",
      "jitter": {
        "timeup": 1000,
        "timedown": 0,
        "value": 500
      },
      "burst": {
        "timeup": 5000,
        "timedown": 5000
      }
    }, {
      "id": 2,
      "name": "Low delay",
      "jitter": {
        "timeup": 1000,
        "timedown": 500,
        "value": 1000
      },
      "burst": {
        "timeup": 6000,
        "timedown": 4000
      }
    } ]
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_post_params_network_scenario_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
изменить один/несколько/все сетевые сценарии доступные ядру

ЗАПРОС (REQUEST): PUT(/params/network_scenario):
{
  "params": {
    "network_scenario": [ {
      "id": number,
      "name": string,
      "jitter": {
        "timeup": number,
        "timedown": number,
        "value": number
      },
      "burst": {
        "timeup": number,
        "timedown": number
      }
    } ]
  }
}

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "params": {
    "network_scenario": [ {
      "id": number,
      "name": string,
      "jitter": {
        "timeup": number,
        "timedown": number,
        "value": number
      },
      "burst": {
        "timeup": number,
        "timedown": number
      }
    } ]
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР ЗАПРОСА:
const char* json_request_put_params_network_scenario_ok = R"(
{
  "params": {
    "network_scenario": [ {
      "id": 1,
      "name": "No change",
      "jitter": {
        "timeup": 1000,
        "timedown": 0,
        "value": 500
      },
      "burst": {
        "timeup": 5000,
        "timedown": 5000
      }
    }, {
      "id": 2,
      "name": "Low delay",
      "jitter": {
        "timeup": 1000,
        "timedown": 500,
        "value": 1000
      },
      "burst": {
        "timeup": 6000,
        "timedown": 4000
      }
    } ]
  }
}
)";

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_put_params_network_scenario_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "network_scenario": [ {
      "id": 1,
      "name": "No change",
      "jitter": {
        "timeup": 1000,
        "timedown": 0,
        "value": 500
      },
      "burst": {
        "timeup": 5000,
        "timedown": 5000
      }
    }, {
      "id": 2,
      "name": "Low delay",
      "jitter": {
        "timeup": 1000,
        "timedown": 500,
        "value": 1000
      },
      "burst": {
        "timeup": 6000,
        "timedown": 4000
      }
    } ]
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_put_params_network_scenario_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "network_scenario": [ {
      "id": 1,
      "name": "No change",
      "jitter": {
        "timeup": 1000,
        "timedown": 0,
        "value": 500
      },
      "burst": {
        "timeup": 5000,
        "timedown": 5000
      }
    }, {
      "id": 2,
      "name": "Low delay",
      "jitter": {
        "timeup": 1000,
        "timedown": 500,
        "value": 1000
      },
      "burst": {
        "timeup": 6000,
        "timedown": 4000
      }
    } ]
  }
}
)";

/*------------------------------------------------------------------------------
удалить один/несколько/все сетевые сценариии доступные ядру

ЗАПРОС (REQUEST): DELETE(/params/network_scenario):
{
  "params": {
    "network_scenario": [ { 
      "id": number,
    } ]
  }
}

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР ЗАПРОСА:
const char* json_request_delete_params_network_scenario = R"(
{
  "params": {
    "network_scenario": [ { 
      "id": 7
    }, { 
      "id": 8
    } ]
  }
}
)";

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_delete_params_network_scenario_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_delete_params_network_scenario_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
получить параметры всех EPS-Bearer

ЗАПРОС (REQUEST): GET(/params/eb):
-

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "params": {
    "eb": [ {
      "id": number,
      "br": number,
      "user_scenario": { 
        "id": number,
        "name": string,
        "br": number,
       "pcap_id": [
          "id": number
        ]
      },
      "network_scenario": {
        "id": number,
        "name": string,
        "jitter": {
          "timeup": number,
          "timedown": number,
          "value": number
        },
        "burst": {
          "timeup": number,
          "timedown": number
        }
      }
    } ]
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_get_params_eb_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "eb": [ {
      "id": 1,
      "br": 40000000,
      "user_scenario": {
        "id": 1
      },
      "network_scenario": {
        "id": 1
      }
    }, {
      "id": 2,
      "br": 50000000,
      "user_scenario": {
        "id": 0,
        "name": "Custom",
        "br": 9000000,
        "pcap_id": [
          1, 2
        ]
      },
      "network_scenario": {
        "id": 0,
        "name": "Custom",
        "jitter": {
          "timeup": 1000,
          "timedown": 0,
          "value": 500
        },
        "burst": {
          "timeup": 5000,
          "timedown": 5000
        }
      }
    } ]
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_get_params_eb_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
получить параметры одного EPS-Bearer указанного в параметре id

ЗАПРОС (REQUEST): GET(/params/eb/1?id=):
-

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "params": {
    "eb": [ {
      "id": number,
      "br": number,
      "user_scenario": { 
        "id": number,
        "name": string,
        "br": number,
       "pcap_id": [
          "id": number
        ]
      },
      "network_scenario": {
        "id": number,
        "name": string,
        "jitter": {
          "timeup": number,
          "timedown": number,
          "value": number
        },
        "burst": {
          "timeup": number,
          "timedown": number
        }
      }
    } ]
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_get_params_eb_1_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "eb": [ {
      "id": 1,
      "br": 40000000,
      "user_scenario": {
        "id": 1
      },
      "network_scenario": {
        "id": 0,
        "name": "Custom",
        "jitter": {
          "timeup": 1000,
          "timedown": 0,
          "value": 500
        },
        "burst": {
          "timeup": 5000,
          "timedown": 5000
        }
      }
    } ]
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_get_params_eb_1_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
создать один/несколько EPS-Bearer с параметрами

ЗАПРОС (REQUEST): POST(/params/eb):
{
  "params": {
    "eb": [ {
      "id": number,
      "br": number,
      "user_scenario": { 
        "id": number,
        "name": string,
        "br": number,
       "pcap_id": [
          "id": number
        ]
      },
      "network_scenario": {
        "id": number,
        "name": string,
        "jitter": {
          "timeup": number,
          "timedown": number,
          "value": number
        },
        "burst": {
          "timeup": number,
          "timedown": number
        }
      }
    } ]
  }
}

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "params": {
    "eb": [ {
      "id": number,
      "br": number,
      "user_scenario": { 
        "id": number,
        "name": string,
        "br": number,
       "pcap_id": [
          "id": number
        ]
      },
      "network_scenario": {
        "id": number,
        "name": string,
        "jitter": {
          "timeup": number,
          "timedown": number,
          "value": number
        },
        "burst": {
          "timeup": number,
          "timedown": number
        }
      }
    } ]
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР ЗАПРОСА:
const char* json_request_post_params_eb = R"(
{
  "params": {
    "eb": [ {
      "id": 1,
      "br": 40000000,
      "user_scenario": {
        "id": 1
      },
      "network_scenario": {
        "id": 1
      }
    }, {
      "id": 2,
      "br": 50000000,
      "user_scenario": {
        "id": 0,
        "name": "Custom",
        "br": 9000000,
        "pcap_id": [
          1, 2
        ]
      },
      "network_scenario": {
        "id": 0,
        "name": "Custom",
        "jitter": {
          "timeup": 1000,
          "timedown": 0,
          "value": 500
        },
        "burst": {
          "timeup": 5000,
          "timedown": 5000
        }
      }
    } ]
  }
}
)";

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_post_params_eb_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "eb": [ {
      "id": 1,
      "br": 40000000,
      "user_scenario": {
        "id": 1
      },
      "network_scenario": {
        "id": 1
      }
    }, {
      "id": 2,
      "br": 50000000,
      "user_scenario": {
        "id": 0,
        "name": "Custom",
        "br": 9000000,
        "pcap_id": [
          1, 2
        ] },
      "network_scenario": {
        "id": 0,
        "name": "Custom",
        "jitter": {
          "timeup": 1000,
          "timedown": 0,
          "value": 500
        },
        "burst": {
          "timeup": 5000,
          "timedown": 5000
        }
      }
    } ]
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_post_params_eb_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
изменить параметры работы для одного/нескольких/всех EPS-Bearer

ЗАПРОС (REQUEST): PUT(/params/eb):
{
  "params": {
    "eb": [ {
      "id": number,
      "br": number,
      "user_scenario": { 
        "id": number,
        "name": string,
        "br": number,
       "pcap_id": [
          "id": number
        ]
      },
      "network_scenario": {
        "id": number,
        "name": string,
        "jitter": {
          "timeup": number,
          "timedown": number,
          "value": number
        },
        "burst": {
          "timeup": number,
          "timedown": number
        }
      }
    } ]
  }
}

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  },
  "params": {
    "eb": [ {
      "id": number,
      "br": number,
      "user_scenario": { 
        "id": number,
        "name": string,
        "br": number,
       "pcap_id": [
          "id": number
        ]
      },
      "network_scenario": {
        "id": number,
        "name": string,
        "jitter": {
          "timeup": number,
          "timedown": number,
          "value": number
        },
        "burst": {
          "timeup": number,
          "timedown": number
        }
      }
    } ]
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР ЗАПРОСА:
const char* json_request_put_params_eb = R"(
{
  "params": {
    "eb": [ {
      "id": 1,
      "br": 40000000,
      "user_scenario": {
        "id": 1
      },
      "network_scenario": {
        "id": 1
      }
    }, {
      "id": 2,
      "br": 50000000,
      "user_scenario": {
        "id": 0,
        "name": "Custom",
        "br": 9000000,
        "pcap_id": [
          1, 2
        ] },
      "network_scenario": {
        "id": 0,
        "name": "Custom",
        "jitter": {
          "timeup": 1000,
          "timedown": 0,
          "value": 500
        },
        "burst": {
          "timeup": 5000,
          "timedown": 5000
        }
      }
    } ]
  }
}
)";

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_put_params_eb_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "eb": [ {
      "id": 1,
      "br": 40000000,
      "user_scenario": {
        "id": 1
      },
      "network_scenario": {
        "id": 1
      }
    }, {
      "id": 2,
      "br": 50000000,
      "user_scenario": {
        "id": 0,
        "name": "Custom",
        "br": 9000000,
        "pcap_id": [
          1, 2
        ] },
      "network_scenario": {
        "id": 0,
        "name": "Custom",
        "jitter": {
          "timeup": 1000,
          "timedown": 0,
          "value": 500
        },
        "burst": {
          "timeup": 5000,
          "timedown": 5000
        }
      }
    } ]
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_put_params_eb_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  },
  "params": {
    "eb": [ {
      "id": 1,
      "br": 40000000,
      "user_scenario": {
        "id": 1
      },
      "network_scenario": {
        "id": 1
      }
    }, {
      "id": 2,
      "br": 50000000,
      "user_scenario": {
        "id": 0,
        "name": "Custom",
        "br": 9000000,
        "pcap_id": [
          1, 2
        ] },
      "network_scenario": {
        "id": 0,
        "name": "Custom",
        "jitter": {
          "timeup": 1000,
          "timedown": 0,
          "value": 500
        },
        "burst": {
          "timeup": 5000,
          "timedown": 5000
        }
      }
    } ]
  }
}
)";

/*------------------------------------------------------------------------------
удалить один/несколько/все EPS-Bearer

ЗАПРОС (REQUEST): DELETE(/params/eb):
{
  "params": {
    "eb": [ {
      "id": number
    } ]
  }
}

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР ЗАПРОСА:
const char* json_request_delete_params_eb = R"(
{
  "params": {
    "eb": [ {
      "id": 1
    }, {
      "id": 2
    } ]
  }
}
)";

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_delete_params_eb_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_delete_params_eb_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

/*------------------------------------------------------------------------------
ЗАПРОС (REQUEST): 

ОТВЕТ (RESPONSE) в формате JSON:
{
  "response": {
    "code": number,
    "time": string
  }
}

КОДЫ ОТВЕТА:
0 - Ok
1 - Неизвестная ошибка
*/

//ПРИМЕР УСПЕШНОГО ОТВЕТА:
const char* json_response_ok = R"(
{
  "response": {
    "code": 0,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

//ПРИМЕР ОШИБОЧНОГО ОТВЕТА:
const char* json_response_err = R"(
{
  "response": {
    "code": 1,
    "time": "2021-10-06T04:34:21.1436"
  }
}
)";

