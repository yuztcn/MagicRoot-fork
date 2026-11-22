#ifndef PC98260_TARGET_H
#define PC98260_TARGET_H
#ifdef PC98260_TARGET_GA812
#include "pc98260_target_ga812.h"
#elif defined(PC98260_TARGET_G893)
#include "pc98260_target_g893.h"
#else
#include "pc98260_target_6658.h"
#endif
#endif
