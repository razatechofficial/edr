package features

import "math"

const MemoryInjectionFeatureCount = 32

type hasMalfindIndicators interface {
	GetInjectionCount() int
	GetTotalProcesses() int
	GetCommitCharge() float64
	GetSuspiciousProtectionScore() float64
	GetUniqueInjections() int
}

type hasPsxviewAnomalies interface {
	GetNotInPslist() int
	GetNotInEprocessPool() int
	GetNotInEthreadPool() int
	GetNotInPspcidList() int
	GetNotInCsrssHandles() int
	GetNotInSession() int
	GetNotInDeskthrd() int
}

type hasLdrmoduleAnomalies interface {
	GetNotInLoadAvg() float64
	GetNotInInitAvg() float64
	GetNotInMemAvg() float64
}

type hasHandleStats interface {
	GetNprocess() int
	GetNthread() int
	GetNsection() int
	GetTotalHandles() int
	GetHandleDiversity() int
}

type hasProcessStats interface {
	GetNprocs64bit() int
	GetAvgThreads() float64
	GetAvgHandlers() float64
}

type hasKernelAnomalies interface {
	GetNcallbacks() int
	GetNanonymous() int
	GetKernelDrivers() int
	GetTotalServices() int
	GetHiddenServices() int
}

type hasVolatilityFalseAvg interface {
	GetNotInPslistFalseAvg() float64
	GetNotInEprocessPoolFalseAvg() float64
	GetNotInCsrssHandlesFalseAvg() float64
	GetNotInDeskthrdFalseAvg() float64
}

type MemoryInjectionFeatureExtractor struct{}

func (e *MemoryInjectionFeatureExtractor) Extract(evt interface{}) []float32 {
	feats := make([]float32, MemoryInjectionFeatureCount)

	if mi, ok := evt.(hasMalfindIndicators); ok {
		total := mi.GetTotalProcesses()
		if total > 0 {
			feats[0] = float32(math.Min(float64(mi.GetInjectionCount())/float64(total), 1.0))
		}
		feats[1] = float32(math.Min(mi.GetCommitCharge()/100.0, 1.0))
		feats[2] = float32(math.Min(mi.GetSuspiciousProtectionScore(), 1.0))
		feats[3] = float32(math.Min(float64(mi.GetUniqueInjections())/10.0, 1.0))
	}

	if px, ok := evt.(hasPsxviewAnomalies); ok {
		total := px.GetNotInPslist() + px.GetNotInEprocessPool() + 1
		feats[4] = float32(math.Min(float64(px.GetNotInPslist())/float64(total), 1.0))
		feats[5] = float32(math.Min(float64(px.GetNotInEprocessPool())/float64(total), 1.0))
		feats[6] = float32(math.Min(float64(px.GetNotInCsrssHandles())/float64(total), 1.0))

		composite := (px.GetNotInPslist() + px.GetNotInEprocessPool() +
			px.GetNotInEthreadPool() + px.GetNotInPspcidList() +
			px.GetNotInCsrssHandles() + px.GetNotInSession() +
			px.GetNotInDeskthrd()) / 7
		feats[7] = float32(math.Min(float64(composite)/10.0, 1.0))
	}

	if ld, ok := evt.(hasLdrmoduleAnomalies); ok {
		feats[8] = float32(math.Min(ld.GetNotInLoadAvg(), 1.0))
		feats[9] = float32(math.Min(ld.GetNotInInitAvg(), 1.0))
		feats[10] = float32(math.Min(ld.GetNotInMemAvg(), 1.0))
		feats[11] = float32(math.Min(
			(ld.GetNotInLoadAvg()+ld.GetNotInInitAvg()+ld.GetNotInMemAvg())/2.0, 1.0))
	}

	if hs, ok := evt.(hasHandleStats); ok {
		total := hs.GetTotalHandles()
		if total > 0 {
			feats[12] = float32(math.Min(float64(hs.GetNprocess())/float64(total)*5.0, 1.0))
			feats[13] = float32(math.Min(float64(hs.GetNthread())/float64(total)*5.0, 1.0))
			feats[14] = float32(math.Min(float64(hs.GetNsection())/float64(total)*5.0, 1.0))
		}
		feats[15] = float32(math.Min(float64(hs.GetHandleDiversity())/20.0, 1.0))
	}

	if ps, ok := evt.(hasProcessStats); ok {
		feats[16] = float32(math.Min(float64(ps.GetNprocs64bit())/50.0, 1.0))
		feats[17] = float32(math.Min(ps.GetAvgThreads()/30.0, 1.0))
		feats[18] = float32(math.Min(ps.GetAvgHandlers()/500.0, 1.0))
	}

	if ka, ok := evt.(hasKernelAnomalies); ok {
		feats[20] = float32(math.Min(float64(ka.GetNcallbacks())/100.0, 1.0))
		totalCallbacks := ka.GetNcallbacks()
		if totalCallbacks > 0 {
			feats[21] = float32(math.Min(float64(ka.GetNanonymous())/float64(totalCallbacks), 1.0))
		}
		totalSvcs := ka.GetTotalServices()
		if totalSvcs > 0 {
			feats[22] = float32(float64(ka.GetKernelDrivers()) / float64(totalSvcs))
			feats[23] = float32(float64(ka.GetHiddenServices()) / float64(totalSvcs))
		}
	}

	if fa, ok := evt.(hasVolatilityFalseAvg); ok {
		feats[24] = float32(math.Min(fa.GetNotInPslistFalseAvg(), 1.0))
		feats[25] = float32(math.Min(fa.GetNotInEprocessPoolFalseAvg(), 1.0))
		feats[26] = float32(math.Min(fa.GetNotInCsrssHandlesFalseAvg(), 1.0))
		feats[27] = float32(math.Min(fa.GetNotInDeskthrdFalseAvg(), 1.0))
	}

	feats[28] = float32(math.Min(
		float64(feats[0])*float64(feats[1])*10.0+
			float64(feats[2])*float64(feats[3])*5.0, 1.0))

	feats[29] = float32(math.Min(
		float64(feats[4])+float64(feats[5])+
			float64(feats[6])+float64(feats[7]), 1.0))

	feats[30] = float32(math.Min(
		float64(feats[8])+float64(feats[9])+
			float64(feats[10])+float64(feats[11]), 1.0))

	feats[31] = float32(math.Min(
		(float64(feats[28])*0.4+float64(feats[29])*0.3+
			float64(feats[30])*0.3)*2.0, 1.0))

	return feats
}
