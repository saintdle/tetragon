// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"net/http"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/podhooks"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

var (
	registry            *prometheus.Registry
	registryOnce        sync.Once
	metricsWithPod      []*prometheus.MetricVec
	metricsWithPodMutex sync.RWMutex
	podQueue            workqueue.DelayingInterface
	podQueueOnce        sync.Once
	deleteDelay         = 1 * time.Minute
)

// NewCounterVecWithPod is a wrapper around prometheus.NewCounterVec that also registers the metric
// to be cleaned up when a pod is deleted. It should be used only to register metrics that have
// "pod" and "namespace" labels.
func NewCounterVecWithPod(opts prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
	metric := prometheus.NewCounterVec(opts, labels)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}

// NewGaugeVecWithPod is a wrapper around prometheus.NewGaugeVec that also registers the metric
// to be cleaned up when a pod is deleted. It should be used only to register metrics that have
// "pod" and "namespace" labels.
func NewGaugeVecWithPod(opts prometheus.GaugeOpts, labels []string) *prometheus.GaugeVec {
	metric := prometheus.NewGaugeVec(opts, labels)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}

// NewHistogramVecWithPod is a wrapper around prometheus.NewHistogramVec that also registers the metric
// to be cleaned up when a pod is deleted. It should be used only to register metrics that have
// "pod" and "namespace" labels.
func NewHistogramVecWithPod(opts prometheus.HistogramOpts, labels []string) *prometheus.HistogramVec {
	metric := prometheus.NewHistogramVec(opts, labels)
	metricsWithPodMutex.Lock()
	metricsWithPod = append(metricsWithPod, metric.MetricVec)
	metricsWithPodMutex.Unlock()
	return metric
}

// RegisterPodDeleteHandler registers handler for deleting metrics associated
// with deleted pods. Without it, Tetragon kept exposing stale metrics for
// deleted pods. This was causing continuous increase in memory usage in
// Tetragon agent as well as in the metrics scraper.
func RegisterPodDeleteHandler() {
	logger.GetLogger().Info("Registering pod delete handler for metrics")
	podhooks.RegisterCallbacksAtInit(podhooks.Callbacks{
		PodCallbacks: func(podInformer cache.SharedIndexInformer) {
			podInformer.AddEventHandler(
				cache.ResourceEventHandlerFuncs{
					DeleteFunc: func(obj interface{}) {
						var pod *corev1.Pod
						switch concreteObj := obj.(type) {
						case *corev1.Pod:
							pod = concreteObj
						case cache.DeletedFinalStateUnknown:
							// Handle the case when the watcher missed the deletion event
							// (e.g. due to a lost apiserver connection).
							deletedObj, ok := concreteObj.Obj.(*corev1.Pod)
							if !ok {
								return
							}
							pod = deletedObj
						default:
							return
						}
						queue := GetPodQueue()
						queue.AddAfter(pod, deleteDelay)
					},
				},
			)
		},
	})
}

func GetPodQueue() workqueue.DelayingInterface {
	podQueueOnce.Do(func() {
		podQueue = workqueue.NewDelayingQueue()
	})
	return podQueue
}

func DeleteMetricsForPod(pod *corev1.Pod) {
	for _, metric := range ListMetricsWithPod() {
		metric.DeletePartialMatch(prometheus.Labels{
			"pod":       pod.Name,
			"namespace": pod.Namespace,
		})
	}
}

func ListMetricsWithPod() []*prometheus.MetricVec {
	// NB: All additions to the list happen when registering metrics, so it's safe to just return
	// the list here.
	return metricsWithPod
}

func GetRegistry() *prometheus.Registry {
	registryOnce.Do(func() {
		registry = prometheus.NewRegistry()
	})
	return registry
}

func StartPodDeleteHandler() {
	queue := GetPodQueue()
	for {
		pod, quit := queue.Get()
		if quit {
			return
		}
		DeleteMetricsForPod(pod.(*corev1.Pod))
	}
}

func EnableMetrics(address string) {
	reg := GetRegistry()

	logger.GetLogger().WithField("addr", address).Info("Starting metrics server")
	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	http.ListenAndServe(address, nil)
}
