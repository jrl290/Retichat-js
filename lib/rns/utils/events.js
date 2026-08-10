class EventEmitter {

    constructor() {
        this.eventListenersMap = new Map();
    }

    on(event, callback) {

        // create list of listeners for event if it doesn't exist
        if(!this.eventListenersMap.has(event)){
            this.eventListenersMap.set(event, []);
        }

        // add listener for event
        this.eventListenersMap.get(event).push(callback);

    }

    off(event, callback) {

        // remove callback from listeners for this event
        if(this.eventListenersMap.has(event)){
            const callbacks = this.eventListenersMap.get(event).filter(cb => cb !== callback);
            this.eventListenersMap.set(event, callbacks);
        }

    }

    once(event, callback) {

        // Removing the listener is not enough on its own: emit() defers every
        // invocation with setTimeout, so two emits in the same tick both capture
        // this wrapper before the first one runs and can remove it. The flag is
        // what actually makes this fire-once. Callers depend on that — a second
        // "concluded" would hand the app a duplicate resource.
        let fired = false;
        const wrapper = (...data) => {
            if(fired){
                return;
            }
            fired = true;
            this.off(event, wrapper);
            callback(...data);
        };
        this.on(event, wrapper);

    }

    emit(event, ...data) {

        // invoke each listener for this event
        if(this.eventListenersMap.has(event)){
            for(const eventListener of this.eventListenersMap.get(event)){
                setTimeout(() => eventListener(...data), 0);
            }
        }

    }

}

export default EventEmitter;
